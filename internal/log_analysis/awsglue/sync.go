package awsglue

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"context"
	goerr "errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
)

type SyncTask struct {
	DryRun      bool
	NumRequests int
	Logger      *zap.Logger
	Table       *glue.TableData
	TimeBin     GlueTableTimebin
	GlueClient  *glue.Glue
	S3Client    *s3.S3
}

func ListLogTables(ctx context.Context, client *glue.Glue) ([]*glue.TableData, error) {
	var tables []*glue.TableData
	scanPage := func(page *glue.GetTablesOutput, _ bool) bool {
		tables = append(tables, page.TableList...)
		return true
	}
	input := &glue.GetTablesInput{
		DatabaseName: aws.String(LogProcessingDatabaseName),
	}
	if err := client.GetTablesPagesWithContext(ctx, input, scanPage); err != nil {
		return nil, err
	}
	return tables, nil
}

type PartitionScanFunc func(p *glue.Partition, tm time.Time) bool

func (s *SyncTask) ScanPartitions(ctx context.Context, scanRange *ScanRange, scan PartitionScanFunc) (result ScanSummary, err error) {
	tbl := s.Table
	input := glue.GetPartitionsInput{
		TableName:    tbl.Name,
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
	}
	if expr := scanRange.PartitionFilter(s.TimeBin); expr != "" {
		input.Expression = &expr
	}
	scanPage := func(page *glue.GetPartitionsOutput, _ bool) bool {
		for _, p := range page.Partitions {
			if tm, ok := partitionTime(s.TimeBin, p); ok {
				result.ObservePartition(tm)
				if !scan(p, tm) {
					return false
				}
			}
		}
		return true
	}
	err = s.GlueClient.GetPartitionsPagesWithContext(ctx, &input, scanPage)
	return
}

func (s *SyncTask) Sync(ctx context.Context, start, end time.Time) (*SyncSummary, error) {
	log := s.log()
	scanRange := ScanRange{
		Start: start.UTC(),
		End:   end.UTC(),
	}
	partitions := make(chan *glue.Partition)
	scan := func(p *glue.Partition, tm time.Time) bool {
		if !s.NeedsUpdate(p) {
			log.Debug("skip partition update", zap.Time("partitionTime", tm))
			return true
		}
		log.Debug("partition needs update", zap.Time("partitionTime", tm))
		select {
		case <-ctx.Done():
			return false
		case partitions <- p:
			return true
		}
	}
	wg := sync.WaitGroup{}
	var scanError error
	var scanResult ScanSummary
	wg.Add(1)
	go func(partitions chan<- *glue.Partition) {
		defer close(partitions)
		defer wg.Done()
		scanResult, scanError = s.ScanPartitions(ctx, &scanRange, scan)
		if scanError != nil {
			log.Error("scan failed", zap.Any("scanResult", &scanResult), zap.Error(scanError))
		} else {
			log.Debug("scan finished", zap.Any("scanResult", &scanResult))
		}
	}(partitions)
	numWorkers := s.numWorkers()
	// Record worker results without concurrency issues
	workerResults := make([]SyncSummary, numWorkers)
	for i := 0; i < numWorkers; i++ {
		result := &workerResults[i]
		wg.Add(1)
		go func(partitions <-chan *glue.Partition) {
			defer wg.Done()
			for p := range partitions {
				if !s.NeedsUpdate(p) {
					continue
				}
				if s.DryRun {
					result.NumDiff++
					tm, _ := partitionTime(s.TimeBin, p)
					log.Debug("dry run: skipping partition sync", zap.Time("partitionTime", tm))
					continue
				}
				if err := s.syncPartition(ctx, p); err != nil {
					result.syncErrors = append(result.syncErrors, err)
				} else {
					result.NumSynced++
				}
			}
		}(partitions)
	}
	log.Debug("waiting for workers to finish")
	wg.Wait()
	// Combine all sync results
	result := CombineSyncSummaries(append(workerResults, SyncSummary{
		ScanSummary: scanResult,
	})...)
	return &result, multierr.Append(scanError, result.Err())
}

func (s *SyncTask) syncPartition(ctx context.Context, p *glue.Partition) error {
	tbl := s.Table
	desc := *p.StorageDescriptor
	desc.Columns = s.Table.StorageDescriptor.Columns
	input := glue.UpdatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		PartitionInput: &glue.PartitionInput{
			LastAccessTime:    p.LastAccessTime,
			LastAnalyzedTime:  p.LastAnalyzedTime,
			Parameters:        p.Parameters,
			StorageDescriptor: &desc,
			Values:            p.Values,
		},
		PartitionValueList: p.Values,
		TableName:          tbl.Name,
	}
	_, err := s.GlueClient.UpdatePartitionWithContext(ctx, &input)
	return err
}

func (s *SyncTask) NeedsUpdate(p *glue.Partition) bool {
	want := s.Table.StorageDescriptor.Columns
	have := p.StorageDescriptor.Columns
	//s.Logger.Debug("diff", zap.Any("colsWant", want), zap.Any("colsHave", have))
	if len(want) != len(have) {
		return true
	}
	return !reflect.DeepEqual(want, have)
}

func (s *SyncTask) FindS3PartitionAt(ctx context.Context, tm time.Time) (string, error) {
	tbl := s.Table
	bucket, tblPrefix, err := ParseS3URL(*tbl.StorageDescriptor.Location)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to parse S3 path for table %q", aws.StringValue(tbl.Name))
	}
	objPrefix := tblPrefix + s.TimeBin.PartitionS3PathFromTime(tm)
	listObjectsInput := s3.ListObjectsV2Input{
		Bucket:  aws.String(bucket),
		Prefix:  aws.String(objPrefix),
		MaxKeys: aws.Int64(1),
	}
	hasData := false
	onPage := func(page *s3.ListObjectsV2Output, isLast bool) bool {
		for _, obj := range page.Contents {
			if aws.Int64Value(obj.Size) > 0 {
				hasData = true
				return false
			}
		}
		return true
	}
	if err := s.S3Client.ListObjectsV2PagesWithContext(ctx, &listObjectsInput, onPage); err != nil {
		return "", err
	}
	if !hasData {
		return "", errors.Wrapf(errS3ObjectNotFound, "no partition data for %q at %s", aws.StringValue(tbl.Name), tm)
	}
	return fmt.Sprintf("s3://%s/%s", bucket, objPrefix), nil
}

func (s *SyncTask) FindPartitionAt(ctx context.Context, tm time.Time) (*glue.Partition, error) {
	tbl := s.Table
	input := glue.GetPartitionInput{
		CatalogId:       tbl.CatalogId,
		DatabaseName:    tbl.DatabaseName,
		TableName:       tbl.Name,
		PartitionValues: s.TimeBin.PartitionValuesFromTime(tm),
	}
	output, err := s.GlueClient.GetPartitionWithContext(ctx, &input)
	if err != nil {
		return nil, err
	}
	return output.Partition, nil
}

var errS3ObjectNotFound = goerr.New("s3 object not found")

func (s *SyncTask) RepairPartitionAt(ctx context.Context, tm time.Time) (*glue.Partition, bool, error) {
	s3Location, err := s.FindS3PartitionAt(ctx, tm)
	if err != nil {
		return nil, false, err
	}
	tbl := s.Table
	desc := *tbl.StorageDescriptor // copy because we will mutate
	desc.Location = aws.String(s3Location)
	partitionValues := s.TimeBin.PartitionValuesFromTime(tm)
	createPartitionInput := glue.CreatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		PartitionInput: &glue.PartitionInput{
			Values:            partitionValues,
			StorageDescriptor: &desc,
		},
	}
	p := &glue.Partition{
		CatalogId:         tbl.CatalogId,
		DatabaseName:      tbl.DatabaseName,
		StorageDescriptor: &desc,
		TableName:         tbl.Name,
		Values:            partitionValues,
	}
	// Do not create new partitions if we're on a dry run
	if s.DryRun {
		return p, false, nil
	}
	if _, err = s.GlueClient.CreatePartitionWithContext(ctx, &createPartitionInput); err != nil {
		// Someone else might have created the partition since we last called FindPartitionAt
		if IsAlreadyExistsError(err) {
			return nil, false, err
		}
		return p, false, err
	}
	return p, true, nil
}

func IsEntityNotFoundError(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		return awsErr.Code() == glue.ErrCodeEntityNotFoundException
	}
	return false
}

func IsAlreadyExistsError(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		return awsErr.Code() == glue.ErrCodeAlreadyExistsException
	}
	return false
}

func (s *SyncTask) log() *zap.Logger {
	log := s.Logger
	if log == nil {
		log = zap.NewNop()
	}
	return log.With(
		zap.String("tableName", aws.StringValue(s.Table.Name)),
		zap.String("databaseName", aws.StringValue(s.Table.DatabaseName)),
	)
}

func (s *SyncTask) numWorkers() int {
	numWorkers := s.NumRequests
	if numWorkers < 1 {
		numWorkers = 1
	}
	return numWorkers
}

type ScanRange struct {
	Start time.Time
	End   time.Time
}

func (s *ScanRange) PartitionFilter(tb GlueTableTimebin) string {
	if s == nil || s.Start.IsZero() && s.End.IsZero() {
		return ""
	}
	if s.Start.IsZero() {
		return tb.PartitionsBefore(s.End)
	}
	if s.End.IsZero() {
		return tb.PartitionsAfter(s.End)
	}
	return tb.PartitionsBetween(s.Start, s.End)
}

// Repair scans the partitions to find all available partition times and scans s3 to find missing partitions and restore them
func (s *SyncTask) Repair(ctx context.Context, start, end time.Time) (*RepairSummary, error) {
	scanRange, err := s.buildScanRange(start, end)
	if err != nil {
		return &RepairSummary{}, err
	}
	existingPartitions := map[time.Time]struct{}{}
	scan := func(p *glue.Partition, tm time.Time) bool {
		existingPartitions[tm] = struct{}{}
		return true
	}
	scanResult, err := s.ScanPartitions(ctx, scanRange, scan)
	if err != nil {
		return &RepairSummary{ScanSummary: scanResult}, err
	}
	repairTimes := make(chan time.Time)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go func(out chan<- time.Time) {
		defer wg.Done()
		defer close(out)
		for tm := scanRange.Start; tm.Before(scanRange.End); tm = s.TimeBin.Next(tm) {
			if _, exists := existingPartitions[tm]; exists {
				continue
			}
			select {
			case out <- tm:
			case <-ctx.Done():
				return
			}
		}
	}(repairTimes)

	numWorkers := s.numWorkers()
	// Record worker results without concurrency issues
	workerResults := make([]RepairSummary, numWorkers)
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		// Pick the worker's result slot
		result := &workerResults[i]
		go func(ch <-chan time.Time) {
			defer wg.Done()
			for tm := range ch {
				_, repaired, err := s.RepairPartitionAt(ctx, tm)
				result.ObserveRepair(tm, repaired, err)
			}
		}(repairTimes)
	}
	wg.Wait()
	// Merge all results
	result := CombineRepairSummaries(append(workerResults, RepairSummary{
		ScanSummary: scanResult,
	})...)
	return &result, result.Err()
}

type ScanSummary struct {
	// Number of partitions in the table
	NumPartitions int64
	// Min partition time
	MinTime time.Time
	// Max partition time
	MaxTime time.Time
}

type RepairSummary struct {
	ScanSummary
	// Number of S3 object scans performed
	NumS3Miss int64
	// Number of partitions found in S3
	NumS3Hit int64
	// Number of partitions synced successfully
	NumRepaired  int64
	repairErrors []error
}

func CombineRepairSummaries(results ...RepairSummary) (out RepairSummary) {
	for _, r := range results {
		out.NumPartitions += r.NumPartitions
		out.NumRepaired += r.NumRepaired
		out.NumS3Miss += r.NumS3Miss
		out.NumS3Hit += r.NumS3Hit
		out.ObserveMinTime(r.MinTime)
		out.ObserveMaxTime(r.MaxTime)
		out.repairErrors = append(out.repairErrors, r.repairErrors...)
	}
	return
}

func (r *ScanSummary) ObserveMinTime(tm time.Time) {
	if r.MinTime.IsZero() || r.MinTime.After(tm) {
		r.MinTime = tm
	}
}
func (r *ScanSummary) ObserveMaxTime(tm time.Time) {
	if r.MaxTime.Before(tm) {
		r.MaxTime = tm
	}
}

func (r *ScanSummary) ObservePartition(tm time.Time) {
	r.NumPartitions++
	r.ObserveMaxTime(tm)
	r.ObserveMinTime(tm)
}

func (r *RepairSummary) Err() error {
	return multierr.Combine(r.repairErrors...)
}

func partitionTime(bin GlueTableTimebin, p *glue.Partition) (time.Time, bool) {
	return bin.PartitionTimeFromValues(aws.StringValueSlice(p.Values))
}

type SyncSummary struct {
	ScanSummary
	// Number of partitions with different columns from table
	NumDiff int64
	// Number of partitions synced successfully
	NumSynced int64
	// Accumuate all sync errors here
	syncErrors []error
}

func CombineSyncSummaries(results ...SyncSummary) (out SyncSummary) {
	for _, r := range results {
		out.NumSynced += r.NumSynced
		out.NumDiff += r.NumDiff
		out.NumPartitions += r.NumPartitions
		out.syncErrors = append(out.syncErrors, r.syncErrors...)
		out.ObserveMinTime(out.MinTime)
		out.ObserveMaxTime(out.MaxTime)
	}
	return
}

func (r *SyncSummary) Err() error {
	return multierr.Combine(r.syncErrors...)
}

func (r *RepairSummary) ObserveRepair(tm time.Time, created bool, err error) {
	if err != nil {
		if IsAlreadyExistsError(err) {
			r.NumS3Hit++
			r.ObservePartition(tm)
			return
		}
		if errors.Is(err, errS3ObjectNotFound) {
			r.NumS3Miss++
			return
		}
		r.repairErrors = append(r.repairErrors, err)
		return
	}
	r.NumS3Hit++
	// Dry run will not create the partition
	if created {
		r.NumRepaired++
		r.ObservePartition(tm)
	}
}
func (s *SyncTask) buildScanRange(start, end time.Time) (*ScanRange, error) {
	var createdAt time.Time
	if s.Table != nil && s.Table.CreateTime != nil {
		createdAt = *s.Table.CreateTime
	}
	if start.IsZero() {
		start = createdAt
	}
	if end.IsZero() {
		end = time.Now()
	}
	start = start.UTC()
	start = s.TimeBin.Truncate(start)
	end = end.UTC()
	if start.Before(end) {
		return &ScanRange{
			Start: start,
			End:   end,
		}, nil
	}
	return nil, errors.Errorf("invalid time range %s %s", start, end)
}

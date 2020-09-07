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
	"path"
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

// ListLogTables returns a list of available tables in the log processing database
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

// ScanPartitions scans all Glue partitions in a time range
func (s *SyncTask) ScanPartitions(ctx context.Context, start, end time.Time, scan PartitionScanFunc) (result ScanSummary, err error) {
	log := s.log()
	tbl := s.Table
	input := glue.GetPartitionsInput{
		CatalogId:    tbl.CatalogId,
		TableName:    tbl.Name,
		DatabaseName: tbl.DatabaseName,
		MaxResults:   aws.Int64(1000),
	}
	if end.IsZero() {
		end = time.Now()
	}
	scanRange := ScanRange{
		Start: start,
		End:   end,
	}
	if expr := scanRange.PartitionFilter(s.TimeBin); expr != "" {
		input.Expression = &expr
	}
	scanPage := func(page *glue.GetPartitionsOutput, _ bool) bool {
		log.Debug("partition page", zap.Int("numPartitions", len(page.Partitions)))
		result.NumPages++
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
	log.Debug("partition scan complete", zap.Any("scanResult", &result))

	return
}

// Sync scans all Glue partitions in a time range and updates their descriptors to match the table descriptor.
func (s *SyncTask) Sync(ctx context.Context, start, end time.Time) (*SyncSummary, error) {
	log := s.log()
	type task struct {
		Partition *glue.Partition
		Time      time.Time
	}
	tasks := make(chan *task)
	wg, numWorkers := newWaitGroup(s.NumRequests)
	// Record worker results without concurrency issues
	results := make([]SyncSummary, numWorkers)
	for i := 0; i < numWorkers; i++ {
		result := &results[i]
		go func(tasks <-chan *task) {
			defer wg.Done()
			for p := range tasks {
				if !needsUpdate(s.Table, p.Partition) {
					continue
				}
				result.NumDiff++
				if s.DryRun {
					continue
				}
				if err := s.syncPartition(ctx, p.Partition); err != nil {
					result.syncErrors = append(result.syncErrors, err)
				} else {
					result.NumSynced++
				}
			}
		}(tasks)
	}
	// Scan partitions
	scanResult, scanError := s.ScanPartitions(ctx, start, end, func(p *glue.Partition, tm time.Time) bool {
		select {
		case <-ctx.Done():
			return false
		case tasks <- &task{p, tm}:
			return true
		}
	})
	// Wait for workers to finish
	close(tasks)
	wg.Wait()

	// Combine all sync results
	results = append(results, SyncSummary{
		ScanSummary: scanResult,
	})
	result := CombineSyncSummaries(results...)
	log.Debug("sync complete", zap.Any("syncResult", &result))
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

func needsUpdate(tbl *glue.TableData, p *glue.Partition) bool {
	want := tbl.StorageDescriptor.Columns
	have := p.StorageDescriptor.Columns
	//s.Logger.Debug("diff", zap.Any("colsWant", want), zap.Any("colsHave", have))
	if len(want) != len(have) {
		return true
	}
	return !reflect.DeepEqual(want, have)
}

// FindS3PartitionAt scans S3 to find partition data at the specified time.
func (s *SyncTask) FindS3PartitionAt(ctx context.Context, tm time.Time) (string, error) {
	tbl := s.Table
	bucket, tblPrefix, err := ParseS3URL(*tbl.StorageDescriptor.Location)
	if err != nil {
		return "", errors.WithMessagef(err, "failed to parse S3 path for table %q", aws.StringValue(tbl.Name))
	}
	objPrefix := path.Join(tblPrefix, s.TimeBin.PartitionS3PathFromTime(tm)) + "/"
	listObjectsInput := s3.ListObjectsV2Input{
		Bucket: aws.String(bucket),
		Prefix: aws.String(objPrefix),
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

var errS3ObjectNotFound = goerr.New("s3 object not found")

// RecoverPartitionAt tries to recover a Glue partition by scanning S3 for data.
func (s *SyncTask) RecoverPartitionAt(ctx context.Context, tm time.Time) (*glue.Partition, bool, error) {
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

// IsEntityNotFoundError checks if an AWS error has an EntityNotFoundException code.
func IsEntityNotFoundError(err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		return awsErr.Code() == glue.ErrCodeEntityNotFoundException
	}
	return false
}

// IsAlreadyExistsError checks if an AWS error has an AlreadyExistsException code.
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

func newWaitGroup(n int) (*sync.WaitGroup, int) {
	if n < 1 {
		n = 1
	}
	wg := &sync.WaitGroup{}
	wg.Add(n)
	return wg, n
}

type ScanRange struct {
	Start time.Time
	End   time.Time
}

func (s *ScanRange) PartitionFilter(tb GlueTableTimebin) string {
	if s.Start.IsZero() && s.End.IsZero() {
		return ""
	}
	if s.Start.IsZero() {
		return tb.PartitionsBefore(s.End.UTC())
	}
	if s.End.IsZero() {
		return tb.PartitionsAfter(s.Start.UTC())
	}
	return tb.PartitionsBetween(s.Start.UTC(), s.End.UTC())
}

func (s *SyncTask) ScanDatePartitions(ctx context.Context, tm time.Time) (map[time.Time]*glue.Partition, error) {
	tm = tm.UTC()
	filter := fmt.Sprintf(`year = %d AND month = %d AND day = %d`, tm.Year(), tm.Month(), tm.Day())
	reply, err := s.GlueClient.GetPartitionsWithContext(ctx, &glue.GetPartitionsInput{
		DatabaseName: s.Table.DatabaseName,
		TableName:    s.Table.Name,
		Expression:   &filter,
	})
	if err != nil {
		return nil, err
	}
	partitions := make(map[time.Time]*glue.Partition, 24)
	for _, p := range reply.Partitions {
		tm, ok := partitionTime(s.TimeBin, p)
		if !ok {
			continue
		}
		partitions[tm] = p
	}
	return partitions, nil
}

// Recover date tries to recover Glue partitions for a specific date
func (s *SyncTask) RecoverDate(ctx context.Context, tm time.Time) (*RecoverResult, error) {
	partitions, err := s.ScanDatePartitions(ctx, tm)
	if err != nil {
		return nil, err
	}
	if len(partitions) == 24 {
		return nil, err
	}
	start := GlueTableDaily.Truncate(tm)
	end := GlueTableDaily.Next(start)

	var recover []*glue.PartitionInput
	// Iterate over each hour in the day
	for tm := start; tm.Before(end); tm = GlueTableHourly.Next(tm) {
		// Skip an hour if a partition already exists
		if _, ok := partitions[tm]; ok {
			continue
		}
		// Check to see if there are data for this partition in S3
		location, err := s.FindS3PartitionAt(ctx, tm)
		if err != nil {
			// No data found, skip to the next hour
			if errors.Is(err, errS3ObjectNotFound) {
				continue
			}
			return nil, err
		}
		// We found a partition to be recovered
		desc := *s.Table.StorageDescriptor
		desc.Location = aws.String(location)
		recover = append(recover, &glue.PartitionInput{
			StorageDescriptor: &desc,
			Values:            GlueTableHourly.PartitionValuesFromTime(tm),
		})
	}

	result := RecoverResult{
		StartDate: start,
		EndDate:   end,
	}

	if len(recover) == 0 {
		return &result, nil
	}

	// Recover all partitions with a single API call
	reply, err := s.GlueClient.BatchCreatePartitionWithContext(ctx, &glue.BatchCreatePartitionInput{
		CatalogId:          s.Table.CatalogId,
		DatabaseName:       s.Table.DatabaseName,
		TableName:          s.Table.Name,
		PartitionInputList: recover,
	})
	if err != nil {
		result.NumFailed = len(recover)
		return &result, errors.Wrapf(err, "failed to recover %d partitions", len(recover))
	}
	result.NumRecovered = len(recover)
	// Collect errors
	for _, e := range reply.Errors {
		// Decrement recovered
		result.NumRecovered--
		// This will ignore AlreadyExists errors
		if e := s.recoverError(e); e != nil {
			result.NumFailed++
			err = multierr.Append(err, e)
		}
	}
	return &result, err
}

// RecoverResult summarizes the results of a recover task
type RecoverResult struct {
	StartDate    time.Time
	EndDate      time.Time
	NumRecovered int
	NumFailed    int
}

func (s *SyncTask) recoverError(p *glue.PartitionError) error {
	if p == nil || p.ErrorDetail == nil {
		return nil
	}
	code := aws.StringValue(p.ErrorDetail.ErrorCode)
	if code == glue.ErrCodeAlreadyExistsException {
		return nil
	}
	message := aws.StringValue(p.ErrorDetail.ErrorMessage)
	tm, _ := GlueTableHourly.PartitionTimeFromValues(aws.StringValueSlice(p.PartitionValues))
	tableName := aws.StringValue(s.Table.Name)
	// Using fmt.Errorf to not add stack
	err := fmt.Errorf("failed to recover Glue partition %s@%s", tableName, tm)
	return awserr.New(code, message, err)
}

// Recover tries to restore partitions at a time range
// It first scans the Glue partitions to know which ones already exist between start and end.
// It then iterates through the time range and scans the table's S3 bucket for objects matching the partitions of the
// missing timestamps.
func (s *SyncTask) Recover(ctx context.Context, start, end time.Time) (*RecoverResult, error) {
	scanRange, err := buildScanRange(s.Table, start, end)
	if err != nil {
		return nil, err
	}

	type taskResult struct {
		Result *RecoverResult
		Err    error
	}
	// Start parallel workers for each day
	tasks := make(chan time.Time)
	wg, numWorkers := newWaitGroup(s.NumRequests)
	// Collect worker results in this channel
	results := make(chan *taskResult, numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(tasks <-chan time.Time) {
			defer wg.Done()
			for tm := range tasks {
				r, err := s.RecoverDate(ctx, tm)
				results <- &taskResult{
					Result: r,
					Err:    err,
				}
			}
		}(tasks)
	}
	go func() {
		// NOTE: Order of defer items is reverse
		// 3. Close result channel once all workers have finished
		defer close(results)
		// 2. Wait for workers to finish
		defer wg.Wait()
		// 1. Close the tasks channel so worker loops stop
		defer close(tasks)

		// Send tasks to workers
		for tm := scanRange.Start; tm.Before(scanRange.End); tm = GlueTableDaily.Next(tm) {
			select {
			case tasks <- tm:
			case <-ctx.Done():
				// Update the range to reflect the range that got processed
				scanRange.End = tm
				return
			}
		}
	}()

	// Collect results
	out := RecoverResult{}
	for r := range results {
		if r := r.Result; r != nil {
			out.NumRecovered += r.NumRecovered
			out.NumFailed += r.NumFailed
		}
		err = multierr.Append(err, r.Err)
	}
	// Set the processed range
	out.StartDate = scanRange.Start
	out.EndDate = scanRange.End
	return &out, err
}

// ScanSummary summarizes the results of a Glue partition scan
type ScanSummary struct {
	// Number of partitions in the table
	NumPartitions int64
	// Number of partition pages during scan
	NumPages int64
	// Min partition time
	MinTime time.Time
	// Max partition time
	MaxTime time.Time
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

func partitionTime(bin GlueTableTimebin, p *glue.Partition) (time.Time, bool) {
	return bin.PartitionTimeFromValues(aws.StringValueSlice(p.Values))
}

// SyncSummary summarizes the results of a sync task
type SyncSummary struct {
	ScanSummary
	// Number of partitions with different columns from table
	NumDiff int64
	// Number of partitions synced successfully
	NumSynced int64
	// Accumulate all sync errors here
	syncErrors []error
}

// CombineSyncSummaries aggregates sync summaries
func CombineSyncSummaries(results ...SyncSummary) (out SyncSummary) {
	for _, r := range results {
		out.NumSynced += r.NumSynced
		out.NumDiff += r.NumDiff
		out.NumPages += r.NumPages
		out.NumPartitions += r.NumPartitions
		out.syncErrors = append(out.syncErrors, r.syncErrors...)
		out.ObserveMinTime(r.MinTime)
		out.ObserveMaxTime(r.MaxTime)
	}
	return
}

func (r *SyncSummary) Err() error {
	return multierr.Combine(r.syncErrors...)
}

func buildScanRange(tbl *glue.TableData, start, end time.Time) (*ScanRange, error) {
	if start.IsZero() {
		start = aws.TimeValue(tbl.CreateTime)
	}
	if end.IsZero() {
		end = time.Now()
	}
	start = GlueTableDaily.Truncate(start.UTC())
	end = GlueTableDaily.Truncate(end.UTC())
	if start.Equal(end) {
		end = GlueTableDaily.Next(start)
	}
	if start.Before(end) {
		return &ScanRange{
			Start: start,
			End:   end,
		}, nil
	}
	const layoutDaily = "2006-01-02"
	return nil, errors.Errorf("invalid time range %s %s", start.Format(layoutDaily), end.Format(layoutDaily))
}

package awsglue

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/pkg/errors"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"reflect"
	"sync"
	"time"
)

type SyncTask struct {
	Concurrency int
	DryRun      bool
	Table       *glue.TableData
	TimeBin     GlueTableTimebin
	GlueClient  *glue.Glue
	S3Client    *s3.S3
	Logger      *zap.Logger

	partitions <-chan *glue.Partition
	done       <-chan struct{}
	minTime    time.Time
	maxTime    time.Time
	err        error
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
	numWorkers := s.Concurrency
	if numWorkers < 1 {
		numWorkers = 1
	}
	return numWorkers
}

func ListLogTables(ctx context.Context, client *glue.Glue) ([]*glue.TableData, error) {
	var tables []*glue.TableData
	onPage := func(page *glue.GetTablesOutput, isLast bool) bool {
		tables = append(tables, page.TableList...)
		return isLast
	}
	input := &glue.GetTablesInput{
		DatabaseName: aws.String(LogProcessingDatabaseName),
	}
	if err := client.GetTablesPagesWithContext(ctx, input, onPage); err != nil {
		return nil, err
	}
	return tables, nil
}

func (s *SyncTask) SyncBetween(ctx context.Context, start, end time.Time) *SyncResult {
	log := s.log().With(zap.Time("scanStart", start), zap.Time("scanEnd", end))
	start = s.TimeBin.Truncate(start.UTC())
	end = end.UTC()
	result := &safeSyncResult{}
	wg := sync.WaitGroup{}

	times := make(chan time.Time)
	wg.Add(1)
	go func(out chan<- time.Time) {
		defer wg.Done()
		defer close(times)
		start = s.TimeBin.Truncate(start.UTC())
		end = end.UTC()
		for tm := start; tm.Before(end); tm = s.TimeBin.Next(tm) {
			select {
			case out <- tm:
			case <-ctx.Done():
				return
			}
		}
	}(times)

	numWorkers := s.numWorkers()
	wg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		go func(ch <-chan time.Time) {
			defer wg.Done()
			for tm := range ch {
				p, err := s.FindOrCreatePartitionAt(ctx, tm)
				if err != nil {
					result.ObserveError(err)
					continue
				}
				if p == nil {
					log.Debug("no partition or data found", zap.Time("partitionTime", tm))
					continue
				}
				created := p.CreationTime == nil
				result.ObserveScanPartition(tm, created)
				if created {
					log.Debug("recovered partition", zap.Time("partitionTime", tm))
					continue
				}
				if !s.NeedsUpdate(p) {
					log.Debug("partition up to date", zap.Time("partitionTime", tm))
					continue
				}
				log.Debug("updating partition", zap.Time("partitionTime", tm))
				if err := s.syncPartition(ctx, p); err != nil {
					log.Debug("failed to update partition", zap.Time("partitionTime", tm))
					result.ObserveError(err)
					continue
				}
				result.ObserveUpdated()
			}
		}(times)
	}
	wg.Wait()
	return &result.SyncResult
}

func (s *SyncTask) SyncAll(ctx context.Context) *SyncResult {
	return s.sync(ctx, nil)
}

func (s *SyncTask) SyncBefore(ctx context.Context, before time.Time) *SyncResult {
	filterBefore := s.TimeBin.PartitionsBefore(before)
	return s.sync(ctx, &filterBefore)
}

func (s *SyncTask) sync(ctx context.Context, filter *string) *SyncResult {
	log := s.log()
	result := safeSyncResult{}
	wg := sync.WaitGroup{}
	partitions := make(chan *glue.Partition)
	wg.Add(1)
	go func(partitions chan<- *glue.Partition) {
		defer close(partitions)
		defer wg.Done()
		tbl := s.Table
		input := glue.GetPartitionsInput{
			TableName:    tbl.Name,
			CatalogId:    tbl.CatalogId,
			DatabaseName: tbl.DatabaseName,
			Expression:   filter,
		}
		n := 0
		onPage := func(page *glue.GetPartitionsOutput, isLast bool) bool {
			n++
			for _, p := range page.Partitions {
				values := aws.StringValueSlice(p.Values)
				tm, ok := s.TimeBin.PartitionTimeFromValues(values)
				if !ok {
					log.Warn("partition has invalid values", zap.Strings("values", values))
					continue
				}
				result.ObserveScanPartition(tm, false)
				if !s.NeedsUpdate(p) {
					log.Debug("skip partition update", zap.Time("partitionTime", tm))
					continue
				}
				log.Debug("partition needs update", zap.Time("partitionTime", tm))
				select {
				case <-ctx.Done():
					return false
				case partitions <- p:
				}
			}
			return isLast
		}

		if err := s.GlueClient.GetPartitionsPagesWithContext(ctx, &input, onPage); err != nil {
			result.ObserveError(err)
		}
		log.Debug("finished scan", zap.Int("numPages", n))
	}(partitions)

	numWorkers := s.numWorkers()
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(partitions <-chan *glue.Partition) {
			defer wg.Done()
			n := 0
			for p := range partitions {
				n++
				tm, _ := s.partitionTime(p)
				if s.DryRun {
					log.Debug("dry run: skipping partition sync", zap.Time("partitionTime", tm))
					continue
				}
				log.Debug("syncing partition", zap.Time("partitionTime", tm))
				err := s.syncPartition(ctx, p)
				if err != nil {
					result.ObserveError(err)
				} else {
					result.ObserveUpdated()
				}
			}
			log.Debug("sync worker done", zap.Int("numSyncs", n))
		}(partitions)
	}
	log.Debug("waiting for workers to finish")

	wg.Wait()
	log.Debug("done")
	return &result.SyncResult
}

func (s *SyncTask) partitionTime(p *glue.Partition) (time.Time, bool) {
	return s.TimeBin.PartitionTimeFromValues(aws.StringValueSlice(p.Values))
}

type ScanResult struct {
	NumCreated    int64
	NumPartitions int64
	MinTime       time.Time
	MaxTime       time.Time
	Err           error
}

func (r *ScanResult) Observe(tm time.Time) {
	if r.MinTime.IsZero() || tm.Before(r.MinTime) {
		r.MinTime = tm
	}
	if tm.After(r.MaxTime) {
		r.MaxTime = tm
	}
	r.NumPartitions++
}

type syncResult struct {
	Partition *glue.Partition
	Err       error
}

func (s *SyncTask) syncPartitionsParallel(ctx context.Context, partitions <-chan *glue.Partition) <-chan *syncResult {
	n := s.Concurrency
	if n < 1 {
		n = 1
	}
	out := make(chan *syncResult)
	wg := &sync.WaitGroup{}
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			for p := range partitions {
				result := syncResult{
					Partition: p,
					Err:       s.syncPartition(ctx, p),
				}
				select {
				case out <- &result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(out)
		wg.Wait()
	}()
	return out
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

func (s *SyncTask) SyncAfter(ctx context.Context, before time.Time) (*SyncResult, error) {
	panic("not implemented")
}

func (s *SyncTask) Err() error {
	if s.done == nil {
		panic("partition scanner not running")
	}
	<-s.done
	return s.err
}

func (s *SyncTask) Partitions() <-chan *glue.Partition {
	if s.partitions == nil {
		panic("partition scanner not running")
	}
	return s.partitions
}

func (s *SyncTask) CreatePartitionAt(ctx context.Context, tm time.Time) (*glue.Partition, error) {
	tbl := s.Table
	bucket, tblPrefix, err := ParseS3URL(*tbl.StorageDescriptor.Location)
	if err != nil {
		return nil, errors.WithMessagef(err, "failed to parse S3 path for table %q", aws.StringValue(tbl.Name))
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
		return nil, err
	}
	if !hasData {
		return nil, nil
	}
	s3URL := fmt.Sprintf("s3://%s/%s", bucket, objPrefix)
	storageDescriptor := *tbl.StorageDescriptor // copy because we will mutate
	storageDescriptor.Location = aws.String(s3URL)
	partitionValues := s.TimeBin.PartitionValuesFromTime(tm)
	createPartitionInput := glue.CreatePartitionInput{
		CatalogId:    tbl.CatalogId,
		DatabaseName: tbl.DatabaseName,
		PartitionInput: &glue.PartitionInput{
			Values:            partitionValues,
			StorageDescriptor: &storageDescriptor,
		},
	}
	if _, err := s.GlueClient.CreatePartitionWithContext(ctx, &createPartitionInput); err != nil {
		if !IsAlreadyExistsError(err) {
			return nil, err
		}
	}
	return s.FindPartitionAt(ctx, tm)
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

func (s *SyncTask) FindOrCreatePartitionAt(ctx context.Context, tm time.Time) (*glue.Partition, error) {
	p, err := s.FindPartitionAt(ctx, tm)
	if err == nil {
		return p, nil
	}
	if IsEntityNotFoundError(err) {
		return s.CreatePartitionAt(ctx, tm)
	}
	return nil, err
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

type safeSyncResult struct {
	mu sync.Mutex
	SyncResult
}

type SyncResult struct {
	NumPartitions int64
	NumRecovered  int64
	NumUpdated    int64
	LastPage      *string
	NumPages      int64
	MinTime       time.Time
	MaxTime       time.Time
	Err           error
}

func (r *safeSyncResult) ObserveError(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Err = multierr.Append(r.Err, err)
}

func (r *safeSyncResult) ObserveUpdated() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.NumUpdated += 1
}

func (r *safeSyncResult) ObservePage(page *string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.LastPage = page
	r.NumPages++
}
func (r *safeSyncResult) ObserveScanPartition(tm time.Time, created bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.SyncResult.NumPartitions += 1
	if r.MinTime.IsZero() || tm.Before(r.MinTime) {
		r.MinTime = tm
	}
	if r.MaxTime.IsZero() || tm.After(r.MaxTime) {
		r.MaxTime = tm
	}
	if created {
		r.SyncResult.NumRecovered += 1
	}
}

//type ticketQueue struct {
//	tickets chan struct{}
//}
//
//func newTicketQueue(n int) *ticketQueue {
//	if n < 1 {
//		n = 1
//	}
//
//	return &ticketQueue{
//		tickets: make(chan struct{}, n),
//	}
//}
//func (q *ticketQueue) Wait(ctx context.Context) bool {
//	select {
//	case q.tickets <- struct{}{}:
//		return true
//	case <-ctx.Done():
//		return false
//	}
//}
//func (q *ticketQueue) Done(ctx context.Context) {
//	select {
//	case <-q.tickets:
//	case <-ctx.Done():
//	}
//}
//

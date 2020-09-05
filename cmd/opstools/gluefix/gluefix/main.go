package gluefix

import (
	"context"
	"flag"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"log"
	"time"
)

var opts = struct {
	SyncBefore  *string
	DryRun      *bool
	Debug       *bool
	Region      *string
	NumRequests *int
	MaxRetries  *int
}{
	SyncBefore:  flag.String("before", "", "Fix partitions before this date YYYY-MM-DD (defaults to table creation time)"),
	DryRun:      flag.Bool("dry-run", false, "Scan for partitions to update without applying any modifications"),
	Debug:       flag.Bool("debug", false, "Enable additional logging"),
	Region:      flag.String("region", "", "Set the AWS region to run on"),
	MaxRetries:  flag.Int("max-retries", 5, "Max retries for AWS requests"),
	NumRequests: flag.Int("num-requests", 8, "Number of parallel AWS requests"),
}

func main() {
	flag.Parse()
	logger, err := buildLogger(*opts.Debug)
	if err != nil {
		log.Fatalf("failed to start logger: %s", err)
	}

	sess, err := buildSession(aws.LoggerFunc(logger.Debug))
	if err != nil {
		logger.Fatalf("failed to start AWS session: %s", err)
	}

	var before time.Time
	if optBefore := *opts.SyncBefore; optBefore != "" {
		const layoutDate = "2006-01-02"
		tm, err := time.Parse(layoutDate, optBefore)
		if err != nil {
			logger.Fatalf("could not parse 'before' flag %q (want YYYY-MM-DD): %s", optBefore, err)
		}
		before = tm
	}

	ctx := context.Background()
	glueClient := glue.New(sess)
	tables, err := awsglue.ListLogTables(ctx, glueClient)
	if err != nil {
		logger.Fatalf("failed to load log tables: %s", err)
	}
	logger.Infof("starting to sync partitions for %d tables", len(tables))
	for i, tbl := range tables {
		tableName := aws.StringValue(tbl.Name)
		task := awsglue.SyncTask{
			Concurrency: *opts.NumRequests,
			DryRun:      *opts.DryRun,
			Table:       tbl,
			TimeBin:     awsglue.GlueTableHourly,
			GlueClient:  glueClient,
			Logger:      logger.Desugar(),
		}
		logger.Infof("syncing partitions for %q table (%d/%d)", tableName, i, len(tables))
		var result *awsglue.SyncResult
		if before.IsZero() {
			result = task.SyncAll(ctx)
		} else {
			result = task.SyncBefore(ctx, before)
		}
		logger.Infof("syncing partitions for %q table (%d/%d) results", tableName, i, len(tables))
		if err := result.Err; err != nil {
			logger.Errorf("syncing partitions for %q table failed: %s", tableName, err)
		}
		logger.Infof("number of partitions found: %d", result.NumPartitions)
		if result.NumPartitions > 0 {
			logger.Infof("max partition time: %s", result.MaxTime.Format(time.RFC3339))
			logger.Infof("min partition time: %s", result.MinTime.Format(time.RFC3339))
			logger.Infof("number of partitions updated: %d", result.NumUpdated)
		}
	}
}

func buildSession(logger aws.Logger) (*session.Session, error) {
	logLevel := aws.LogLevel(aws.LogOff)
	if *opts.Debug {
		logLevel = aws.LogLevel(aws.LogDebug)
	}
	config := aws.Config{
		LogLevel:   logLevel,
		Logger:     logger,
		Region:     opts.Region,
		MaxRetries: opts.MaxRetries,
	}
	ss, err := session.NewSession(&config)
	if err != nil {
		return nil, err
	}
	if ss.Config.Region == nil {
		return nil, errors.New("missing AWS region")
	}
	return ss, nil
}

func buildLogger(debug bool) (*zap.SugaredLogger, error) {
	config := zap.NewDevelopmentConfig()
	// Always disable and file/line numbers, error traces and use color-coded log levels and short timestamps
	config.DisableCaller = true
	config.DisableStacktrace = true
	config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	if !debug {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}
	logger, err := config.Build()
	if err != nil {
		return nil, err
	}
	return logger.Sugar(), nil
}

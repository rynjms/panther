package main

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
	"flag"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/glue"
	"github.com/pkg/errors"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/panther-labs/panther/internal/log_analysis/awsglue"
)

var opts = struct {
	SyncEnd       *string
	SyncStart     *string
	DryRun        *bool
	Debug         *bool
	Recover       *bool
	Region        *string
	NumRequests   *int
	MaxRetries    *int
	LogTypePrefix *string
}{
	SyncStart:     flag.String("start", "", "Fix partitions after this date YYYY-MM-DD"),
	SyncEnd:       flag.String("end", "", "Fix partitions until this date YYYY-MM-DD"),
	Recover:       flag.Bool("recover", false, "Try to recover missing partitions by scanning S3 (slow)"),
	DryRun:        flag.Bool("dry-run", false, "Scan for partitions to update without applying any modifications"),
	Debug:         flag.Bool("debug", false, "Enable additional logging"),
	Region:        flag.String("region", "", "Set the AWS region to run on"),
	MaxRetries:    flag.Int("max-retries", 5, "Max retries for AWS requests"),
	NumRequests:   flag.Int("num-requests", 8, "Number of parallel AWS requests"),
	LogTypePrefix: flag.String("prefix", "", "A prefix to filter log type names"),
}

func main() {
	flag.Parse()
	logger, err := buildLogger(*opts.Debug)
	if err != nil {
		log.Fatalf("failed to start logger: %s", err)
	}

	sess, err := buildSession()
	if err != nil {
		logger.Fatalf("failed to start AWS session: %s", err)
	}

	var start, end time.Time
	if opt := *opts.SyncEnd; opt != "" {
		const layoutDate = "2006-01-02"
		tm, err := time.Parse(layoutDate, opt)
		if err != nil {
			logger.Fatalf("could not parse 'end' flag %q (want YYYY-MM-DD): %s", opt, err)
		}
		end = tm
	}
	if opt := *opts.SyncStart; opt != "" {
		const layoutDate = "2006-01-02"
		tm, err := time.Parse(layoutDate, opt)
		if err != nil {
			logger.Fatalf("could not parse 'start' flag %q (want YYYY-MM-DD): %s", opt, err)
		}
		start = tm
	}

	var match *regexp.Regexp
	if optPrefix := *opts.LogTypePrefix; optPrefix != "" {
		pattern := fmt.Sprintf("^%s", awsglue.GetTableName(optPrefix))
		re, err := regexp.Compile(pattern)
		if err != nil {
			logger.Fatalf("invalid log type prefix %q: %s", optPrefix, err)
		}
		match = re
	}

	task := awsglue.SyncTask{
		NumRequests: *opts.NumRequests,
		DryRun:      *opts.DryRun,
		Start:       start,
		End:         end,
		GlueClient:  glue.New(sess),
		Logger:      logger.Desugar(),
	}
	ctx := context.Background()
	logger.Infof(" for log tables")
	if *opts.Recover {
		if _, err := task.RecoverDatabase(ctx, awsglue.LogProcessingDatabaseName, match); err != nil {
			logger.Errorf("failed to recover %q: %s", awsglue.LogProcessingDatabaseName, err)
		}
		if _, err := task.RecoverDatabase(ctx, awsglue.RuleMatchDatabaseName, match); err != nil {
			logger.Errorf("failed to recover %q: %s", awsglue.LogProcessingDatabaseName, err)
		}
	} else {
		if _, err := task.SyncDatabase(ctx, awsglue.LogProcessingDatabaseName, match); err != nil {
			logger.Errorf("failed to sync %q: %s", awsglue.LogProcessingDatabaseName, err)
		}
		if _, err := task.SyncDatabase(ctx, awsglue.RuleMatchDatabaseName, match); err != nil {
			logger.Errorf("failed to sync %q: %s", awsglue.LogProcessingDatabaseName, err)
		}
	}
}

func buildSession() (*session.Session, error) {
	logLevel := aws.LogLevel(aws.LogOff)
	config := aws.Config{
		LogLevel:   logLevel,
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

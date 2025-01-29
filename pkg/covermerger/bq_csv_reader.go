// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"

	"cloud.google.com/go/bigquery"
	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/gcs"
	"github.com/google/syzkaller/pkg/validator"
	"github.com/google/uuid"
)

type bqCSVReader struct {
	closers  []io.Closer
	gcsFiles []io.Reader
}

func (r *bqCSVReader) Close() {
	for _, c := range r.closers {
		c.Close()
	}
}

func MakeBQCSVReader() *bqCSVReader {
	return &bqCSVReader{}
}

func (r *bqCSVReader) InitNsRecords(ctx context.Context, ns, filePath, commit string, from, to civil.Date) error {
	if err := validator.AnyError("input validation failed",
		validator.NamespaceName(ns),
		validator.AnyOk(validator.EmptyStr(filePath), validator.KernelFilePath(filePath)),
		validator.AnyOk(validator.EmptyStr(commit), validator.CommitHash(commit)),
	); err != nil {
		return err
	}
	sessionUUID := uuid.New().String()
	gsBucket := "syzbot-temp"
	gsPath := fmt.Sprintf("bq-exports/%s", sessionUUID)
	gsURI := "gs://" + gsBucket + "/" + gsPath + "/*.csv.gz"
	client, err := bigquery.NewClient(ctx, "syzkaller")
	if err != nil {
		return fmt.Errorf("failed to initialize bigquery client: %w", err)
	}
	if err := client.EnableStorageReadClient(ctx); err != nil {
		return fmt.Errorf("failed to client.EnableStorageReadClient: %w", err)
	}
	selectCommit := ""
	if commit != "" {
		selectCommit = fmt.Sprintf("AND\n\t\t\t\t\tkernel_commit = \"%s\"", commit)
	}
	q := client.Query(fmt.Sprintf(`
		EXPORT DATA
			OPTIONS (
				uri = "%s",
				format = "CSV",
				overwrite = true,
				header = true,
				compression = "GZIP")
			AS (
				SELECT
					kernel_repo, kernel_branch, kernel_commit, file_path, func_name, manager, sl, SUM(hit_count) as hit_count
				FROM syzkaller.syzbot_coverage.`+"`%s`"+`
				WHERE
					TIMESTAMP_TRUNC(timestamp, DAY) >= "%s" AND
					TIMESTAMP_TRUNC(timestamp, DAY) <= "%s" AND
					version = 1 AND
					starts_with(file_path, "%s") %s
				GROUP BY file_path, func_name, manager, kernel_commit, kernel_repo, kernel_branch, sl
				ORDER BY file_path, manager
			);
	`, gsURI, ns, from.String(), to.String(), filePath, selectCommit))
	job, err := q.Run(ctx)
	if err != nil {
		return fmt.Errorf("err during bigquery.Run: %w", err)
	}
	status, err := job.Wait(ctx)
	if err != nil {
		return fmt.Errorf("err waiting for the bigquery.Job: %w", err)
	}
	if status.Err() != nil {
		return fmt.Errorf("bigquery job failed with status %w", status.Err())
	}
	return r.initGCSFileReaders(ctx, gsBucket, gsPath)
}

func (r *bqCSVReader) initGCSFileReaders(ctx context.Context, bucket, path string) error {
	var gcsClient *gcs.Client
	var err error
	if gcsClient, err = gcs.NewClient(ctx); err != nil {
		return fmt.Errorf("err creating gcs client: %w", err)
	}
	var gcsFiles []*gcs.Object
	if gcsFiles, err = gcsClient.ListObjects(bucket + "/" + path); err != nil {
		return fmt.Errorf("err enumerating gcs files: %w", err)
	}
	for _, obj := range gcsFiles {
		var file *gcs.File
		if file, err = gcsClient.Read(bucket + "/" + obj.Path); err != nil {
			return fmt.Errorf("failed to start reading %s: %w", obj.Path, err)
		}
		var readCloser io.ReadCloser
		if readCloser, err = file.Reader(); err != nil {
			return fmt.Errorf("failed to get %s reader: %w", obj.Path, err)
		}
		r.closers = append(r.closers, readCloser)
		r.gcsFiles = append(r.gcsFiles, readCloser)
	}
	return nil
}

func (r *bqCSVReader) Reader() (io.Reader, error) {
	var readers []io.Reader
	for _, file := range r.gcsFiles {
		gzipReaderCloser, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("err calling gzip.NewReader: %w", err)
		}
		r.closers = append(r.closers, gzipReaderCloser)
		readers = append(readers, gzipReaderCloser)
	}
	return io.MultiReader(readers...), nil
}

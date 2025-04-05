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

func InitNsRecords(ctx context.Context, ns, filePath, commit string, from, to civil.Date) (io.ReadCloser, error) {
	if err := validator.AnyError("input validation failed",
		validator.NamespaceName(ns),
		validator.AnyOk(validator.EmptyStr(filePath), validator.KernelFilePath(filePath)),
		validator.AnyOk(validator.EmptyStr(commit), validator.CommitHash(commit)),
	); err != nil {
		return nil, err
	}
	sessionUUID := uuid.New().String()
	gsBucket := "syzbot-temp"
	gsPath := fmt.Sprintf("bq-exports/%s", sessionUUID)
	gsURI := "gs://" + gsBucket + "/" + gsPath + "/*.csv.gz"
	client, err := bigquery.NewClient(ctx, "syzkaller")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize bigquery client: %w", err)
	}
	if err := client.EnableStorageReadClient(ctx); err != nil {
		return nil, fmt.Errorf("failed to client.EnableStorageReadClient: %w", err)
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
		return nil, fmt.Errorf("err during bigquery.Run: %w", err)
	}
	status, err := job.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("err waiting for the bigquery.Job: %w", err)
	}
	if status.Err() != nil {
		return nil, fmt.Errorf("bigquery job failed with status %w", status.Err())
	}
	return initGCSMultiReader(ctx, gsBucket, gsPath)
}

func initGCSMultiReader(ctx context.Context, bucket, path string) (io.ReadCloser, error) {
	var gcsClient gcs.Client
	var err error
	if gcsClient, err = gcs.NewClient(ctx); err != nil {
		return nil, fmt.Errorf("err creating gcs client: %w", err)
	}
	var gcsFiles []*gcs.Object
	if gcsFiles, err = gcsClient.ListObjects(bucket + "/" + path); err != nil {
		return nil, fmt.Errorf("err enumerating gcs files: %w", err)
	}
	paths := []string{}
	for _, obj := range gcsFiles {
		paths = append(paths, bucket+"/"+obj.Path)
	}
	return &gcsGZIPMultiReader{
		gcsClient: gcsClient,
		gcsFiles:  paths,
	}, nil
}

type gcsGZIPMultiReader struct {
	gcsClient gcs.Client
	gcsFiles  []string

	curFileReader   io.ReadCloser
	curGZReadCloser io.ReadCloser
}

func (mr *gcsGZIPMultiReader) Read(p []byte) (int, error) {
	for len(mr.gcsFiles) > 0 {
		if mr.curFileReader == nil {
			var err error
			if mr.curFileReader, err = mr.gcsClient.FileReader(mr.gcsFiles[0]); err != nil {
				return 0, fmt.Errorf("failed to get %s reader: %w", mr.gcsFiles[0], err)
			}
			if mr.curGZReadCloser, err = gzip.NewReader(mr.curFileReader); err != nil {
				mr.curGZReadCloser = nil // gzip.NewReader returns *Reader(nil) on corrupted header
				return 0, fmt.Errorf("err calling gzip.NewReader: %w", err)
			}
		}
		n, err := mr.curGZReadCloser.Read(p)
		if err == io.EOF {
			mr.gcsFiles = mr.gcsFiles[1:]
			if err := mr.Close(); err != nil {
				return 0, fmt.Errorf("mr.Close: %w", err)
			}
		}
		if n > 0 || err != io.EOF {
			if err == io.EOF && len(mr.gcsFiles) > 0 {
				// Don't return EOF yet. More readers remain.
				err = nil
			}
			return n, err
		}
	}
	return 0, io.EOF
}

func (mr *gcsGZIPMultiReader) Close() error {
	var err1, err2 error
	if mr.curGZReadCloser != nil {
		err1 = mr.curGZReadCloser.Close()
	}
	if mr.curFileReader != nil {
		err2 = mr.curFileReader.Close()
	}
	mr.curFileReader = nil
	mr.curGZReadCloser = nil
	if err1 != nil {
		return fmt.Errorf("mr.curGZReadCloser.Close: %w", err1)
	}
	if err2 != nil {
		return fmt.Errorf("mr.curFileReader.Close: %w", err2)
	}
	return nil
}

// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package spanner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sync"
	"sync/atomic"
	"testing"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	instance "cloud.google.com/go/spanner/admin/instance/apiv1"
	"cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"github.com/google/syzkaller/pkg/osutil"
	"google.golang.org/grpc/codes"
)

type ParsedURI struct {
	Project        string
	ProjectPrefix  string // projects/<project>
	InstancePrefix string // projects/<project>/instances/<instance>
	Instance       string
	Database       string
	Full           string
}

var uriRe = regexp.MustCompile(`^projects/([^/]+)/instances/([^/]+)/databases/([^/]+)$`)

func ParseURI(uri string) (ParsedURI, error) {
	ret := ParsedURI{Full: uri}
	matches := uriRe.FindStringSubmatch(uri)
	if matches == nil || len(matches) != 4 {
		return ret, fmt.Errorf("failed to parse %q", uri)
	}
	ret.Project = matches[1]
	ret.ProjectPrefix = "projects/" + matches[1]
	ret.InstancePrefix = ret.ProjectPrefix + "/instances/" + matches[2]
	ret.Instance = matches[2]
	ret.Database = matches[3]
	return ret, nil
}

func CreateSpannerInstance(ctx context.Context, uri ParsedURI) error {
	client, err := instance.NewInstanceAdminClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.GetInstance(ctx, &instancepb.GetInstanceRequest{
		Name: uri.InstancePrefix,
	})
	if err != nil && spanner.ErrCode(err) == codes.NotFound {
		op, err := client.CreateInstance(ctx, &instancepb.CreateInstanceRequest{
			Parent:     uri.ProjectPrefix,
			InstanceId: uri.Instance,
		})
		if err != nil {
			if spanner.ErrCode(err) == codes.AlreadyExists {
				return nil
			}
			return err
		}
		_, err = op.Wait(ctx)
		if err != nil && spanner.ErrCode(err) == codes.AlreadyExists {
			return nil
		}
		return err
	}
	return err
}

func CreateSpannerDB(ctx context.Context, uri ParsedURI, dialect databasepb.DatabaseDialect, ddl []string) error {
	client, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	if ddl == nil {
		_, err = client.GetDatabase(ctx, &databasepb.GetDatabaseRequest{Name: uri.Full})
		if err != nil && spanner.ErrCode(err) != codes.NotFound {
			return err
		}
		if err == nil {
			return nil
		}
	}
	op, err := client.CreateDatabase(ctx, &databasepb.CreateDatabaseRequest{
		Parent:          uri.InstancePrefix,
		CreateStatement: `CREATE DATABASE ` + uri.Database,
		DatabaseDialect: dialect,
		ExtraStatements: ddl,
	})
	if err != nil {
		return err
	}
	_, err = op.Wait(ctx)
	return err
}

var (
	setupSpannerOnce sync.Once
	setupSpannerErr  error
	errSpannerSkip   = errors.New("no spanner emulator binary found, skipping test")
)

func SetupSpannerEmulator(t *testing.T) {
	setupSpannerOnce.Do(func() {
		setupSpannerErr = startSpannerEmulator()
	})
	if setupSpannerErr == errSpannerSkip {
		t.Skip(setupSpannerErr.Error())
	}
	if setupSpannerErr != nil {
		t.Fatalf("failed to setup spanner emulator: %v", setupSpannerErr)
	}
}

func startSpannerEmulator() error {
	bin := os.Getenv("SPANNER_EMULATOR_BIN")
	if bin != "" {
		bin = filepath.Join(filepath.Dir(bin), "emulator_main")
	} else {
		appServerPath, err := exec.LookPath("dev_appserver.py")
		if err == nil {
			bin = filepath.Join(filepath.Dir(appServerPath), "cloud_spanner_emulator", "emulator_main")
		}
	}
	if bin == "" {
		if os.Getenv("CI") != "" || os.Getenv("SYZ_ENV") != "" {
			return errors.New("no spanner emulator binary found")
		}
		return errSpannerSkip
	}
	cmd := osutil.Command(bin, "--host_port", "localhost:0", "--override_max_databases_per_instance=1000")
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	serverAddr := ""
	serverAddrRe := regexp.MustCompile(`Server address: ([\w:]+)`)
	scanner := bufio.NewScanner(stderr)
	for serverAddr == "" && scanner.Scan() {
		if parts := serverAddrRe.FindStringSubmatch(scanner.Text()); parts != nil {
			serverAddr = parts[1]
		}
	}
	if err := scanner.Err(); err != nil {
		cmd.Process.Kill()
		return err
	}
	go io.Copy(io.Discard, stderr)
	if serverAddr == "" {
		cmd.Process.Kill()
		return fmt.Errorf("did not detect the host")
	}
	os.Setenv("SPANNER_EMULATOR_HOST", serverAddr)
	os.Setenv("GOOGLE_CLOUD_SPANNER_MULTIPLEXED_SESSIONS", "false")
	fmt.Printf("started spanner emulator %v on %v\n", bin, serverAddr)
	return nil
}

var testDBSeq atomic.Uint64

func NewTestDB(t *testing.T, dialect databasepb.DatabaseDialect, ddl []string) string {
	SetupSpannerEmulator(t)
	seq := testDBSeq.Add(1)
	uri := fmt.Sprintf("projects/testproject-%d/instances/syzbot/databases/ai", seq)
	parsedURI, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateSpannerInstance(t.Context(), parsedURI); err != nil {
		t.Fatalf("failed CreateSpannerInstance: %v", err)
	}
	if err := CreateSpannerDB(t.Context(), parsedURI, dialect, ddl); err != nil {
		t.Fatalf("failed CreateSpannerDB: %v", err)
	}
	return uri
}

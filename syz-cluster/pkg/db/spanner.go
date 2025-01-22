// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"bufio"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	database "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	instance "cloud.google.com/go/spanner/admin/instance/apiv1"
	"cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"github.com/golang-migrate/migrate/v4"
	migrate_spanner "github.com/golang-migrate/migrate/v4/database/spanner"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
)

type ParsedURI struct {
	ProjectPrefix  string // projects/<project>
	InstancePrefix string // projects/<project>/instances/<instance>
	Instance       string
	Database       string
	Full           string
}

func ParseURI(uri string) (ParsedURI, error) {
	ret := ParsedURI{Full: uri}
	matches := regexp.MustCompile(`projects/(.*)/instances/(.*)/databases/(.*)`).FindStringSubmatch(uri)
	if matches == nil || len(matches) != 4 {
		return ret, fmt.Errorf("failed to parse %q", uri)
	}
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
		_, err = client.CreateInstance(ctx, &instancepb.CreateInstanceRequest{
			Parent:     uri.ProjectPrefix,
			InstanceId: uri.Instance,
		})
		return err
	}
	return err
}

func CreateSpannerDB(ctx context.Context, uri ParsedURI) error {
	client, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	_, err = client.GetDatabase(ctx, &databasepb.GetDatabaseRequest{Name: uri.Full})
	if err != nil && spanner.ErrCode(err) == codes.NotFound {
		op, err := client.CreateDatabase(ctx, &databasepb.CreateDatabaseRequest{
			Parent:          uri.InstancePrefix,
			CreateStatement: `CREATE DATABASE ` + uri.Database,
			ExtraStatements: []string{},
		})
		if err != nil {
			return err
		}
		_, err = op.Wait(ctx)
		return err
	}
	return err
}

func dropSpannerDB(ctx context.Context, uri ParsedURI) error {
	client, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	return client.DropDatabase(ctx, &databasepb.DropDatabaseRequest{Database: uri.Full})
}

//go:embed migrations/*.sql
var migrationsFs embed.FS

func RunMigrations(ctx context.Context, uri string) error {
	sourceDriver, err := iofs.New(migrationsFs, "migrations")
	if err != nil {
		return err
	}
	s := &migrate_spanner.Spanner{}
	dbDriver, err := s.Open("spanner://" + uri + "?x-clean-statements=true")
	if err != nil {
		return err
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "spanner", dbDriver)
	if err != nil {
		return err
	}
	return m.Up()
}

func NewTransientDB(t *testing.T) (*spanner.Client, context.Context) {
	// If the environment contains the emulator binary, start it.
	if bin := os.Getenv("SPANNER_EMULATOR_BIN"); bin != "" {
		host := spannerTestWrapper(t, bin)
		os.Setenv("SPANNER_EMULATOR_HOST", host)
	} else if os.Getenv("CI") != "" {
		// We do want to always run these tests on CI.
		t.Fatalf("CI is set, but SPANNER_EMULATOR_BIN is empty")
	}
	if os.Getenv("SPANNER_EMULATOR_HOST") == "" {
		t.Skip("SPANNER_EMULATOR_HOST must be set")
		return nil, nil
	}
	uri, err := ParseURI("projects/my-project/instances/test-instance/databases/" +
		fmt.Sprintf("db%v", time.Now().UnixNano()))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = CreateSpannerInstance(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	err = CreateSpannerDB(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		err := dropSpannerDB(ctx, uri)
		if err != nil {
			t.Logf("failed to drop the test DB: %v", err)
		}
	})
	client, err := spanner.NewClient(ctx, uri.Full)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	err = RunMigrations(ctx, uri.Full)
	if err != nil {
		t.Fatal(err)
	}
	return client, ctx
}

var setupSpannerOnce sync.Once
var spannerHost string

func spannerTestWrapper(t *testing.T, bin string) string {
	setupSpannerOnce.Do(func() {
		t.Logf("this could be the first test requiring a Spanner emulator, starting %s", bin)
		cmd, host, err := runSpanner(bin)
		if err != nil {
			t.Fatal(err)
		}
		spannerHost = host
		t.Cleanup(func() {
			cmd.Process.Kill()
			cmd.Wait()
		})
	})
	return spannerHost
}

var portRe = regexp.MustCompile(`Server address: ([\w:]+)`)

func runSpanner(bin string) (*exec.Cmd, string, error) {
	cmd := exec.Command(bin, "--override_max_databases_per_instance=1000",
		"--grpc_port=0", "--http_port=0")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, "", err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, "", err
	}
	scanner := bufio.NewScanner(stdout)
	started, host := false, ""
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Cloud Spanner Emulator running") {
			started = true
		} else if parts := portRe.FindStringSubmatch(line); parts != nil {
			host = parts[1]
		}
		if started && host != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return cmd, "", err
	}
	// The program may block if we don't read out all the remaining output.
	go io.Copy(io.Discard, stdout)

	if !started {
		return cmd, "", fmt.Errorf("the emulator did not print that it started")
	}
	if host == "" {
		return cmd, "", fmt.Errorf("did not detect the host")
	}
	return cmd, host, nil
}

func readOne[T any](iter *spanner.RowIterator) (*T, error) {
	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var obj T
	err = row.ToStruct(&obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

func readEntities[T any](iter *spanner.RowIterator) ([]*T, error) {
	var ret []*T
	for {
		obj, err := readOne[T](iter)
		if err != nil {
			return nil, err
		}
		if obj == nil {
			break
		}
		ret = append(ret, obj)
	}
	return ret, nil
}

type genericEntityOps[EntityType, KeyType any] struct {
	client   *spanner.Client
	keyField string
	table    string
}

func (g *genericEntityOps[EntityType, KeyType]) GetByID(ctx context.Context, key KeyType) (*EntityType, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM " + g.table + " WHERE " + g.keyField + "=@key",
		Params: map[string]interface{}{"key": key},
	}
	iter := g.client.Single().Query(ctx, stmt)
	defer iter.Stop()
	return readOne[EntityType](iter)
}

var ErrEntityNotFound = errors.New("entity not found")

func (g *genericEntityOps[EntityType, KeyType]) Update(ctx context.Context, key KeyType,
	cb func(*EntityType) error) error {
	_, err := g.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			stmt := spanner.Statement{
				SQL:    "SELECT * from `" + g.table + "` WHERE `" + g.keyField + "`=@key",
				Params: map[string]interface{}{"key": key},
			}
			iter := txn.Query(ctx, stmt)
			entity, err := readOne[EntityType](iter)
			iter.Stop()
			if err != nil {
				return err
			}
			if entity == nil {
				return ErrEntityNotFound
			}
			err = cb(entity)
			if err != nil {
				return err
			}
			m, err := spanner.UpdateStruct(g.table, entity)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{m})
		})
	return err
}

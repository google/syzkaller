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
	"path/filepath"
	"regexp"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"cloud.google.com/go/spanner/admin/instance/apiv1"
	"cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"github.com/golang-migrate/migrate/v4"
	migrate_spanner "github.com/golang-migrate/migrate/v4/database/spanner"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/syzkaller/pkg/osutil"
	"google.golang.org/api/iterator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func CreateSpannerDB(ctx context.Context, uri ParsedURI, ddl []string) error {
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
		ExtraStatements: ddl,
	})
	if err != nil {
		return err
	}
	_, err = op.Wait(ctx)
	return err
}

//go:embed migrations/*.sql
var migrationsFs embed.FS

func RunMigrations(uri string) error {
	m, err := getMigrateInstance(uri)
	if err != nil {
		return err
	}
	err = m.Up()
	if err == migrate.ErrNoChange {
		// Not really an error.
		return nil
	}
	return err
}

func getMigrateInstance(uri string) (*migrate.Migrate, error) {
	sourceDriver, err := iofs.New(migrationsFs, "migrations")
	if err != nil {
		return nil, err
	}
	s := &migrate_spanner.Spanner{}
	dbDriver, err := s.Open("spanner://" + uri + "?x-clean-statements=true")
	if err != nil {
		return nil, err
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "spanner", dbDriver)
	if err != nil {
		return nil, err
	}
	return m, nil
}

func NewTransientDB(t *testing.T) (*spanner.Client, context.Context) {
	uri := "projects/my-project/instances/test-instance/databases/" +
		fmt.Sprintf("db%v", time.Now().UnixNano())
	NewTestDB(t, uri, nil)
	ctx := t.Context()
	client, err := spanner.NewClient(ctx, uri)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	err = RunMigrations(uri)
	if err != nil {
		t.Fatal(err)
	}
	return client, ctx
}

func NewTestDB(t *testing.T, uri string, ddl []string) {
	setupSpannerEmulator(t)
	// Don't bother destroying instances/databases.
	// We create isolated per-test databases, and the emulator is all in-memory.
	// So when the emulator is killed with the test binary, everything is gone.
	parsedURI, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if err := CreateSpannerInstance(t.Context(), parsedURI); err != nil {
		t.Fatalf("failed CreateSpannerInstance: %v", err)
	}
	if err := CreateSpannerDB(t.Context(), parsedURI, ddl); err != nil {
		t.Fatalf("failed CreateSpannerDB: %v", err)
	}
}

var (
	setupSpannerOnce sync.Once
	setupSpannerErr  error
	errSpannerSkip   = errors.New("no spanner emulator binary found, skipping test")
)

func setupSpannerEmulator(t *testing.T) {
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
	// This env is set by syz-env container.
	bin := os.Getenv("SPANNER_EMULATOR_BIN")
	if bin != "" {
		bin = filepath.Join(filepath.Dir(bin), "emulator_main")
	} else {
		// Otherwise check for installed google-cloud-sdk binary.
		appServerPath, err := exec.LookPath("dev_appserver.py")
		if err == nil {
			bin = filepath.Join(filepath.Dir(appServerPath), "cloud_spanner_emulator", "emulator_main")
		}
	}
	if bin == "" {
		// In these contexts we expect the binary to be present.
		if os.Getenv("CI") != "" || os.Getenv("SYZ_ENV") != "" {
			return errors.New("no spanner emulator binary found")
		}
		return errSpannerSkip
	}
	// Use osutil.Command to set PDEATHSIG.
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
		return err
	}
	// The program may block if we don't read out all the remaining output.
	go io.Copy(io.Discard, stderr)
	if serverAddr == "" {
		return fmt.Errorf("did not detect the host")
	}
	os.Setenv("SPANNER_EMULATOR_HOST", serverAddr)
	// Without this connections to emulator hang, probably some bug somewhere.
	os.Setenv("GOOGLE_CLOUD_SPANNER_MULTIPLEXED_SESSIONS", "false")
	fmt.Printf("started spanner emulator %v on %v\n", bin, serverAddr)
	return nil
}

func readRow[T any](iter *spanner.RowIterator) (*T, error) {
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

type dbQuerier interface {
	Query(context.Context, spanner.Statement) *spanner.RowIterator
}

func readEntity[T any](ctx context.Context, txn dbQuerier, stmt spanner.Statement) (*T, error) {
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()
	return readRow[T](iter)
}

func readRows[T any](iter *spanner.RowIterator) ([]*T, error) {
	var ret []*T
	for {
		obj, err := readRow[T](iter)
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

func readEntities[T any](ctx context.Context, txn dbQuerier, stmt spanner.Statement) ([]*T, error) {
	iter := txn.Query(ctx, stmt)
	defer iter.Stop()
	return readRows[T](iter)
}

const NoLimit = 0

func addLimit(stmt *spanner.Statement, limit int) {
	if limit != NoLimit {
		stmt.SQL += " LIMIT @limit"
		stmt.Params["limit"] = limit
	}
}

type genericEntityOps[EntityType, KeyType any] struct {
	client   *spanner.Client
	keyField string
	table    string
}

func (g *genericEntityOps[EntityType, KeyType]) GetByID(ctx context.Context, key KeyType) (*EntityType, error) {
	stmt := spanner.Statement{
		SQL:    "SELECT * FROM " + g.table + " WHERE " + g.keyField + "=@key",
		Params: map[string]any{"key": key},
	}
	return readEntity[EntityType](ctx, g.client.Single(), stmt)
}

var ErrEntityNotFound = errors.New("entity not found")

func (g *genericEntityOps[EntityType, KeyType]) Update(ctx context.Context, key KeyType,
	cb func(*EntityType) error) error {
	_, err := g.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			entity, err := readEntity[EntityType](ctx, txn, spanner.Statement{
				SQL:    "SELECT * from `" + g.table + "` WHERE `" + g.keyField + "`=@key",
				Params: map[string]any{"key": key},
			})
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

var errEntityExists = errors.New("entity already exists")

func (g *genericEntityOps[EntityType, KeyType]) Insert(ctx context.Context, obj *EntityType) error {
	_, err := g.client.ReadWriteTransaction(ctx,
		func(ctx context.Context, txn *spanner.ReadWriteTransaction) error {
			insert, err := spanner.InsertStruct(g.table, obj)
			if err != nil {
				return err
			}
			return txn.BufferWrite([]*spanner.Mutation{insert})
		})
	if status.Code(err) == codes.AlreadyExists {
		return errEntityExists
	}
	return err
}

func (g *genericEntityOps[EntityType, KeyType]) readEntities(ctx context.Context, stmt spanner.Statement) (
	[]*EntityType, error) {
	return readEntities[EntityType](ctx, g.client.Single(), stmt)
}

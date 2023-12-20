// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
)

type Storage struct {
	cfg     *Config
	backend StorageBackend
	dash    Dashboard
	tracer  debugtracer.DebugTracer
}

type Dashboard interface {
	AddBuildAssets(req *dashapi.AddBuildAssetsReq) error
	NeededAssetsList() (*dashapi.NeededAssetsResp, error)
}

func StorageFromConfig(cfg *Config, dash Dashboard) (*Storage, error) {
	if dash == nil {
		return nil, fmt.Errorf("dashboard api instance is necessary")
	}
	tracer := debugtracer.DebugTracer(&debugtracer.NullTracer{})
	if cfg.Debug {
		tracer = &debugtracer.GenericTracer{
			WithTime:    true,
			TraceWriter: os.Stdout,
		}
	}
	var backend StorageBackend
	if strings.HasPrefix(cfg.UploadTo, "gs://") {
		var err error
		backend, err = makeCloudStorageBackend(strings.TrimPrefix(cfg.UploadTo, "gs://"), tracer)
		if err != nil {
			return nil, fmt.Errorf("the call to MakeCloudStorageBackend failed: %w", err)
		}
	} else if strings.HasPrefix(cfg.UploadTo, "dummy://") {
		backend = makeDummyStorageBackend()
	} else {
		return nil, fmt.Errorf("unknown UploadTo during StorageFromConfig(): %#v", cfg.UploadTo)
	}
	return &Storage{
		cfg:     cfg,
		backend: backend,
		dash:    dash,
		tracer:  tracer,
	}, nil
}

func (storage *Storage) AssetTypeEnabled(assetType dashapi.AssetType) bool {
	return storage.cfg.IsEnabled(assetType)
}

func (storage *Storage) getDefaultCompressor() Compressor {
	return xzCompressor
}

type ExtraUploadArg struct {
	// It is assumed that paths constructed with same UniqueTag values
	// always correspond to an asset having the same content.
	UniqueTag string
	// If the asset being uploaded already exists (see above), don't return
	// an error, abort uploading and return the download URL.
	SkipIfExists bool
}

var ErrAssetTypeDisabled = errors.New("uploading assets of this type is disabled")

func (storage *Storage) assetPath(name string, extra *ExtraUploadArg) string {
	folderName := ""
	if extra != nil && extra.UniqueTag != "" {
		folderName = extra.UniqueTag
	} else {
		// The idea is to make a file name useful and yet unique.
		// So we put a file to a pseudo-unique "folder".
		folderNameBytes := sha256.Sum256([]byte(fmt.Sprintf("%v", time.Now().UnixNano())))
		folderName = fmt.Sprintf("%x", folderNameBytes)
	}
	const folderPrefix = 12
	if len(folderName) > folderPrefix {
		folderName = folderName[0:folderPrefix]
	}
	return fmt.Sprintf("%s/%s", folderName, name)
}

func (storage *Storage) uploadFileStream(reader io.Reader, assetType dashapi.AssetType,
	name string, extra *ExtraUploadArg) (string, error) {
	if name == "" {
		return "", fmt.Errorf("file name is not specified")
	}
	typeDescr := GetTypeDescription(assetType)
	if typeDescr == nil {
		return "", fmt.Errorf("asset type %s is unknown", assetType)
	}
	if !storage.AssetTypeEnabled(assetType) {
		return "", fmt.Errorf("not allowed to upload an asset of type %s: %w",
			assetType, ErrAssetTypeDisabled)
	}
	path := storage.assetPath(name, extra)
	req := &uploadRequest{
		savePath:          path,
		contentType:       typeDescr.ContentType,
		contentEncoding:   typeDescr.ContentEncoding,
		preserveExtension: typeDescr.preserveExtension,
	}
	if req.contentType == "" {
		req.contentType = "application/octet-stream"
	}
	compressor := storage.getDefaultCompressor()
	if typeDescr.customCompressor != nil {
		compressor = typeDescr.customCompressor
	}
	res, err := compressor(req, storage.backend.upload)
	var existsErr *FileExistsError
	if errors.As(err, &existsErr) {
		storage.tracer.Log("asset %s already exists", path)
		if extra == nil || !extra.SkipIfExists {
			return "", err
		}
		// Let's just return the download URL.
		return storage.backend.downloadURL(existsErr.Path, storage.cfg.PublicAccess)
	} else if err != nil {
		return "", fmt.Errorf("failed to query writer: %w", err)
	} else {
		written, err := io.Copy(res.writer, reader)
		if err != nil {
			more := ""
			closeErr := res.writer.Close()
			var exiterr *exec.ExitError
			if errors.As(closeErr, &exiterr) {
				more = fmt.Sprintf(", process state '%s'", exiterr.ProcessState)
			}
			return "", fmt.Errorf("failed to redirect byte stream: copied %d bytes, error %w%s",
				written, err, more)
		}
		err = res.writer.Close()
		if err != nil {
			return "", fmt.Errorf("failed to close writer: %w", err)
		}
	}
	return storage.backend.downloadURL(res.path, storage.cfg.PublicAccess)
}

func (storage *Storage) UploadBuildAsset(reader io.Reader, fileName string, assetType dashapi.AssetType,
	build *dashapi.Build, extra *ExtraUploadArg) (dashapi.NewAsset, error) {
	const commitPrefix = 8
	commit := build.KernelCommit
	if len(commit) > commitPrefix {
		commit = commit[:commitPrefix]
	}
	baseName := filepath.Base(fileName)
	fileExt := filepath.Ext(baseName)
	name := fmt.Sprintf("%s-%s%s",
		strings.TrimSuffix(baseName, fileExt),
		commit,
		fileExt)
	url, err := storage.uploadFileStream(reader, assetType, name, extra)
	if err != nil {
		return dashapi.NewAsset{}, err
	}
	return dashapi.NewAsset{
		Type:        assetType,
		DownloadURL: url,
	}, nil
}
func (storage *Storage) ReportBuildAssets(build *dashapi.Build, assets ...dashapi.NewAsset) error {
	// If the server denies the reques, we'll delete the orphaned file during deprecated files
	// deletion later.
	return storage.dash.AddBuildAssets(&dashapi.AddBuildAssetsReq{
		BuildID: build.ID,
		Assets:  assets,
	})
}

func (storage *Storage) UploadCrashAsset(reader io.Reader, fileName string, assetType dashapi.AssetType,
	extra *ExtraUploadArg) (dashapi.NewAsset, error) {
	url, err := storage.uploadFileStream(reader, assetType, fileName, extra)
	if err != nil {
		return dashapi.NewAsset{}, err
	}
	return dashapi.NewAsset{
		Type:        assetType,
		DownloadURL: url,
	}, nil
}

var ErrAssetDoesNotExist = errors.New("the asset did not exist")

type FileExistsError struct {
	// The path gets changed by wrappers, so we need to return it back.
	Path string
}

func (e *FileExistsError) Error() string {
	return fmt.Sprintf("asset exists: %s", e.Path)
}

var ErrUnknownBucket = errors.New("the asset is not in the currently managed bucket")

const deletionEmbargo = time.Hour * 24 * 7

// Best way: convert download URLs to paths.
// We don't want to risk killing all assets after a slight domain change.
func (storage *Storage) DeprecateAssets() error {
	resp, err := storage.dash.NeededAssetsList()
	if err != nil {
		return fmt.Errorf("failed to query needed assets: %w", err)
	}
	needed := map[string]bool{}
	for _, url := range resp.DownloadURLs {
		path, err := storage.backend.getPath(url)
		if err == ErrUnknownBucket {
			// The asset is not managed by the particular instance.
			continue
		} else if err != nil {
			// If we failed to parse just one URL, let's stop the entire process.
			// Otherwise we'll start deleting still needed files we couldn't recognize.
			return fmt.Errorf("failed to parse '%s': %w", url, err)
		}
		needed[path] = true
	}
	storage.tracer.Log("queried needed assets: %#v", needed)
	existing, err := storage.backend.list()
	if err != nil {
		return fmt.Errorf("failed to query object list: %w", err)
	}
	toDelete := []string{}
	intersection := 0
	for _, obj := range existing {
		keep := false
		if time.Since(obj.createdAt) < deletionEmbargo {
			// To avoid races between object upload and object deletion, we don't delete
			// newly uploaded files for a while after they're uploaded.
			keep = true
		}
		if val, ok := needed[obj.path]; ok && val {
			keep = true
			intersection++
		}
		storage.tracer.Log("-- object %v, %v: keep %t", obj.path, obj.createdAt, keep)
		if !keep {
			toDelete = append(toDelete, obj.path)
		}
	}
	const intersectionCheckCutOff = 4
	if len(existing) > intersectionCheckCutOff && intersection == 0 {
		// This is a last-resort protection against possible dashboard bugs.
		// If the needed assets have no intersection with the existing assets,
		// don't delete anything. Otherwise, if it was a bug, we will lose all files.
		return fmt.Errorf("needed assets have almost no intersection with the existing ones")
	}
	for _, path := range toDelete {
		err := storage.backend.remove(path)
		storage.tracer.Log("-- deleted %v: %v", path, err)
		// Several syz-ci's might be sharing the same storage. So let's tolerate
		// races during file deletion.
		if err != nil && err != ErrAssetDoesNotExist {
			return fmt.Errorf("asset deletion failure: %w", err)
		}
	}
	return nil
}

type uploadRequest struct {
	savePath          string
	contentEncoding   string
	contentType       string
	preserveExtension bool
}

type uploadResponse struct {
	path   string
	writer io.WriteCloser
}

type storedObject struct {
	path      string
	createdAt time.Time
}

type StorageBackend interface {
	upload(req *uploadRequest) (*uploadResponse, error)
	list() ([]storedObject, error)
	remove(path string) error
	downloadURL(path string, publicURL bool) (string, error)
	getPath(url string) (string, error)
}

type Compressor func(req *uploadRequest,
	next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error)

func xzCompressor(req *uploadRequest,
	next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error) {
	newReq := *req
	if !req.preserveExtension {
		newReq.savePath = fmt.Sprintf("%s.xz", newReq.savePath)
	}
	resp, err := next(&newReq)
	if err != nil {
		return nil, err
	}
	xzWriter, err := xz.NewWriter(resp.writer)
	if err != nil {
		return nil, fmt.Errorf("failed to create xz writer: %w", err)
	}
	return &uploadResponse{
		path: resp.path,
		writer: &wrappedWriteCloser{
			writer:        xzWriter,
			closeCallback: resp.writer.Close,
		},
	}, nil
}

const gzipCompressionRatio = 4

// This struct allows to attach a callback on the Close() method invocation of
// an existing io.WriteCloser. Also, it can convert an io.Writer to an io.WriteCloser.
type wrappedWriteCloser struct {
	writer        io.Writer
	closeCallback func() error
}

func (wwc *wrappedWriteCloser) Write(p []byte) (int, error) {
	return wwc.writer.Write(p)
}

func (wwc *wrappedWriteCloser) Close() error {
	var err error
	closer, ok := wwc.writer.(io.Closer)
	if ok {
		err = closer.Close()
	}
	err2 := wwc.closeCallback()
	if err != nil {
		return err
	} else if err2 != nil {
		return err2
	}
	return nil
}

func gzipCompressor(req *uploadRequest,
	next func(req *uploadRequest) (*uploadResponse, error)) (*uploadResponse, error) {
	newReq := *req
	if !req.preserveExtension {
		newReq.savePath = fmt.Sprintf("%s.gz", newReq.savePath)
	}
	resp, err := next(&newReq)
	if err != nil {
		return nil, err
	}
	gzip, err := gzip.NewWriterLevel(resp.writer, gzipCompressionRatio)
	if err != nil {
		resp.writer.Close()
		return nil, err
	}
	return &uploadResponse{
		path: resp.path,
		writer: &wrappedWriteCloser{
			writer: gzip,
			closeCallback: func() error {
				return resp.writer.Close()
			},
		},
	}, nil
}

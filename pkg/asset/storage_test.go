// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package asset

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/stretchr/testify/assert"
	"github.com/ulikunitz/xz"
)

type addBuildAssetCallback func(obj dashapi.NewAsset) error

type dashMock struct {
	downloadURLs  map[string]bool
	addBuildAsset addBuildAssetCallback
}

func newDashMock() *dashMock {
	return &dashMock{downloadURLs: map[string]bool{}}
}

func (dm *dashMock) AddBuildAssets(req *dashapi.AddBuildAssetsReq) error {
	for _, obj := range req.Assets {
		if dm.addBuildAsset != nil {
			if err := dm.addBuildAsset(obj); err != nil {
				return err
			}
		}
		dm.downloadURLs[obj.DownloadURL] = true
	}
	return nil
}

func (dm *dashMock) NeededAssetsList() (*dashapi.NeededAssetsResp, error) {
	resp := &dashapi.NeededAssetsResp{}
	for url := range dm.downloadURLs {
		resp.DownloadURLs = append(resp.DownloadURLs, url)
	}
	return resp, nil
}

func makeStorage(t *testing.T, dash Dashboard) (*Storage, *dummyStorageBackend) {
	be := makeDummyStorageBackend()
	cfg := &Config{
		UploadTo: "dummy://test",
	}
	return &Storage{
		dash:    dash,
		cfg:     cfg,
		backend: be,
		tracer:  &debugtracer.TestTracer{T: t},
	}, be
}

func validateGzip(res *uploadedFile, expected []byte) error {
	if res == nil {
		return fmt.Errorf("no file was uploaded")
	}
	reader, err := gzip.NewReader(bytes.NewReader(res.bytes))
	if err != nil {
		return fmt.Errorf("gzip.NewReader failed: %w", err)
	}
	defer reader.Close()
	body, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("read of ungzipped content failed: %w", err)
	}
	if !reflect.DeepEqual(body, expected) {
		return fmt.Errorf("decompressed: %#v, expected: %#v", body, expected)
	}
	return nil
}

func validateXz(res *uploadedFile, expected []byte) error {
	if res == nil {
		return fmt.Errorf("no file was uploaded")
	}
	xzUsed := strings.HasSuffix(res.req.savePath, ".xz")
	if !xzUsed {
		return fmt.Errorf("xz expected to be used")
	}
	xzReader, err := xz.NewReader(bytes.NewReader(res.bytes))
	if err != nil {
		return fmt.Errorf("xz reader failed: %w", err)
	}
	out, err := io.ReadAll(xzReader)
	if err != nil {
		return fmt.Errorf("xz decompression failed: %w", err)
	}
	if !reflect.DeepEqual(out, expected) {
		return fmt.Errorf("decompressed: %#v, expected: %#v", out, expected)
	}
	return nil
}

func (storage *Storage) sendBuildAsset(reader io.Reader, fileName string, assetType dashapi.AssetType,
	build *dashapi.Build) error {
	asset, err := storage.UploadBuildAsset(reader, fileName, assetType, build, nil)
	if err != nil {
		return err
	}
	return storage.ReportBuildAssets(build, asset)
}

func TestUploadBuildAsset(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(t, dashMock)
	be.currentTime = time.Now().Add(-2 * deletionEmbargo)
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}

	// Upload two assets using different means.
	vmLinuxContent := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	dashMock.addBuildAsset = func(newAsset dashapi.NewAsset) error {
		if newAsset.Type != dashapi.KernelObject {
			t.Fatalf("expected KernelObject, got %v", newAsset.Type)
		}
		if !strings.Contains(newAsset.DownloadURL, "vmlinux") {
			t.Fatalf("%#v was expected to mention vmlinux", newAsset.DownloadURL)
		}
		return nil
	}
	var file *uploadedFile
	be.objectUpload = collectBytes(&file)
	err := storage.sendBuildAsset(bytes.NewReader(vmLinuxContent), "vmlinux",
		dashapi.KernelObject, build)
	if err != nil {
		t.Fatalf("file upload failed: %s", err)
	}
	if err := validateXz(file, vmLinuxContent); err != nil {
		t.Fatalf("vmlinux validation failed: %s", err)
	}
	// Upload the same file the second time.
	storage.sendBuildAsset(bytes.NewReader(vmLinuxContent), "vmlinux", dashapi.KernelObject, build)
	// The currently expected behavior is that it will be uploaded twice and will have
	// different names.
	if len(dashMock.downloadURLs) < 2 {
		t.Fatalf("same-file upload was expected to succeed, but it didn't; %#v", dashMock.downloadURLs)
	}

	diskImageContent := []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8}
	dashMock.addBuildAsset = func(newAsset dashapi.NewAsset) error {
		if newAsset.Type != dashapi.KernelImage {
			t.Fatalf("expected KernelImage, got %v", newAsset.Type)
		}
		if !strings.Contains(newAsset.DownloadURL, "disk") ||
			!strings.Contains(newAsset.DownloadURL, ".img") {
			t.Fatalf("%#v was expected to mention disk.img", newAsset.DownloadURL)
		}
		if !strings.Contains(newAsset.DownloadURL, build.KernelCommit[:6]) {
			t.Fatalf("%#v was expected to mention build commit", newAsset.DownloadURL)
		}
		return nil
	}
	file = nil
	be.objectUpload = collectBytes(&file)
	storage.sendBuildAsset(bytes.NewReader(diskImageContent), "disk.img", dashapi.KernelImage, build)
	if err := validateXz(file, diskImageContent); err != nil {
		t.Fatalf("disk.img validation failed: %s", err)
	}

	allUrls := []string{}
	for url := range dashMock.downloadURLs {
		allUrls = append(allUrls, url)
	}
	if len(allUrls) != 3 {
		t.Fatalf("invalid dashMock state: expected 3 assets, got %d", len(allUrls))
	}
	// First try to remove two assets.
	dashMock.downloadURLs = map[string]bool{allUrls[2]: true, "http://download/unrelated.txt": true}

	// Pretend there's an asset deletion error.
	be.objectRemove = func(string) error { return fmt.Errorf("not now") }
	err = storage.DeprecateAssets()
	if err == nil {
		t.Fatalf("DeprecateAssets() should have failed")
	}

	// Let the deletion be successful.
	be.objectRemove = nil
	err = storage.DeprecateAssets()
	if err != nil {
		t.Fatalf("DeprecateAssets() was expected to be successful, got %s", err)
	}
	path, err := be.getPath(allUrls[2])
	if err != nil {
		t.Fatalf("getPath failed: %s", err)
	}
	err = be.hasOnly([]string{path})
	if err != nil {
		t.Fatalf("after first DeprecateAssets(): %s", err)
	}

	// Delete the rest.
	dashMock.downloadURLs = map[string]bool{}
	err = storage.DeprecateAssets()
	if err != nil || len(be.objects) != 0 {
		t.Fatalf("second DeprecateAssets() failed: %s, len %d",
			err, len(be.objects))
	}
}

type uploadedFile struct {
	req   uploadRequest
	bytes []byte
}

func collectBytes(saveTo **uploadedFile) objectUploadCallback {
	return func(req *uploadRequest) (*uploadResponse, error) {
		buf := &bytes.Buffer{}
		wwc := &wrappedWriteCloser{
			writer: buf,
			closeCallback: func() error {
				*saveTo = &uploadedFile{req: *req, bytes: buf.Bytes()}
				return nil
			},
		}
		return &uploadResponse{path: req.savePath, writer: wwc}, nil
	}
}

func TestUploadHtmlAsset(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(t, dashMock)
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}
	htmlContent := []byte("<html><head><title>Hi!</title></head></html>")
	dashMock.addBuildAsset = func(newAsset dashapi.NewAsset) error {
		if newAsset.Type != dashapi.HTMLCoverageReport {
			t.Fatalf("expected HtmlCoverageReport, got %v", newAsset.Type)
		}
		if !strings.Contains(newAsset.DownloadURL, "cover_report") {
			t.Fatalf("%#v was expected to mention cover_report", newAsset.DownloadURL)
		}
		if !strings.HasSuffix(newAsset.DownloadURL, ".html") {
			t.Fatalf("%#v was expected to have .html extension", newAsset.DownloadURL)
		}
		return nil
	}
	var file *uploadedFile
	be.objectUpload = collectBytes(&file)
	storage.sendBuildAsset(bytes.NewReader(htmlContent), "cover_report.html",
		dashapi.HTMLCoverageReport, build)
	if err := validateGzip(file, htmlContent); err != nil {
		t.Fatalf("cover_report.html validation failed: %s", err)
	}
}

func TestRecentAssetDeletionProtection(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(t, dashMock)
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}
	htmlContent := []byte("<html><head><title>Hi!</title></head></html>")
	be.currentTime = time.Now().Add(-time.Hour * 24 * 6)
	err := storage.sendBuildAsset(bytes.NewReader(htmlContent), "cover_report.html",
		dashapi.HTMLCoverageReport, build)
	if err != nil {
		t.Fatalf("failed to upload a file: %v", err)
	}

	// Try to delete a recent file.
	dashMock.downloadURLs = map[string]bool{}
	err = storage.DeprecateAssets()
	if err != nil {
		t.Fatalf("DeprecateAssets failed: %v", err)
	} else if len(be.objects) == 0 {
		t.Fatalf("a recent object was deleted: %v", err)
	}
}

func TestAssetStorageConfiguration(t *testing.T) {
	dashMock := newDashMock()
	cfg := &Config{
		UploadTo: "dummy://",
		Assets: map[dashapi.AssetType]TypeConfig{
			dashapi.HTMLCoverageReport: {Never: true},
			dashapi.KernelObject:       {},
		},
	}
	storage, err := StorageFromConfig(cfg, dashMock)
	if err != nil {
		t.Fatalf("unexpected error from StorageFromConfig: %s", err)
	}
	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}

	// Uploading a file of a disabled asset type.
	htmlContent := []byte("<html><head><title>Hi!</title></head></html>")
	err = storage.sendBuildAsset(bytes.NewReader(htmlContent), "cover_report.html",
		dashapi.HTMLCoverageReport, build)
	if !errors.Is(err, ErrAssetTypeDisabled) {
		t.Fatalf("UploadBuildAssetStream expected to fail with ErrAssetTypeDisabled, but got %v", err)
	}

	// Uploading a file of an unspecified asset type.
	testContent := []byte{0x1, 0x2, 0x3, 0x4}
	err = storage.sendBuildAsset(bytes.NewReader(testContent), "disk.raw", dashapi.BootableDisk, build)
	if err != nil {
		t.Fatalf("UploadBuildAssetStream of BootableDisk expected to succeed, got %v", err)
	}

	// Uploading a file of a specified asset type.
	err = storage.sendBuildAsset(bytes.NewReader(testContent), "vmlinux", dashapi.KernelObject, build)
	if err != nil {
		t.Fatalf("UploadBuildAssetStream of BootableDisk expected to succeed, got %v", err)
	}
}

func TestUploadSameContent(t *testing.T) {
	dashMock := newDashMock()
	storage, be := makeStorage(t, dashMock)
	be.currentTime = time.Now().Add(-2 * deletionEmbargo)

	build := &dashapi.Build{ID: "1234", KernelCommit: "abcdef2134"}
	extra := &ExtraUploadArg{UniqueTag: "uniquetag", SkipIfExists: true}
	testContent := []byte{0x1, 0x2, 0x3, 0x4}
	asset, err := storage.UploadBuildAsset(bytes.NewReader(testContent), "disk.raw",
		dashapi.BootableDisk, build, extra)
	if err != nil {
		t.Fatalf("UploadBuildAssetexpected to succeed, got %v", err)
	}
	if !strings.Contains(asset.DownloadURL, extra.UniqueTag) {
		t.Fatalf("%#v was expected to contain %#v", asset.DownloadURL, extra.UniqueTag)
	}
	// Upload the same asset again.
	be.objectUpload = func(req *uploadRequest) (*uploadResponse, error) {
		return nil, &FileExistsError{req.savePath}
	}
	assetTwo, err := storage.UploadBuildAsset(bytes.NewReader(testContent), "disk.raw",
		dashapi.BootableDisk, build, extra)
	if err != nil {
		t.Fatalf("UploadBuildAssetexpected to succeed, got %v", err)
	}
	if asset.DownloadURL != assetTwo.DownloadURL {
		t.Fatalf("assets were expected to have same download URL, got %#v %#v",
			asset.DownloadURL, assetTwo.DownloadURL)
	}
}

// Test that we adequately handle the case when several syz-cis with separate buckets
// are connected to a single dashboard.
// nolint: dupl
func TestTwoBucketDeprecation(t *testing.T) {
	dash := newDashMock()
	storage, dummy := makeStorage(t, dash)

	// "Upload" an asset from this instance.
	resp, _ := dummy.upload(&uploadRequest{
		savePath: `folder/file.txt`,
	})
	url, _ := dummy.downloadURL(resp.path, true)

	// Dashboard returns two asset URLs.
	dash.downloadURLs = map[string]bool{
		"http://unknown-bucket/other-folder/other-file.txt": true, // will cause ErrUnknownBucket
		url: true,
	}
	dummy.objectRemove = func(url string) error {
		t.Fatalf("Unexpected removal")
		return nil
	}
	err := storage.DeprecateAssets()
	assert.NoError(t, err)
}

// nolint: dupl
func TestInvalidAssetURLs(t *testing.T) {
	dash := newDashMock()
	storage, dummy := makeStorage(t, dash)

	// "Upload" an asset from this instance.
	resp, _ := dummy.upload(&uploadRequest{
		savePath: `folder/file.txt`,
	})
	url, _ := dummy.downloadURL(resp.path, true)

	// Dashboard returns two asset URLs.
	dash.downloadURLs = map[string]bool{
		"http://totally-unknown-bucket/other-folder/other-file.txt": true,
		url: true,
	}
	dummy.objectRemove = func(url string) error {
		t.Fatalf("Unexpected removal")
		return nil
	}
	err := storage.DeprecateAssets()
	assert.Error(t, err)
}

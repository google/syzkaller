// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package orcarouter implements an AI backend for the OrcaRouter gateway.
//
// OrcaRouter is an OpenAI-compatible AI gateway for authorised security
// engineering work: https://www.orcarouter.ai/cyber. Inference and model
// discovery are served from https://api.orcarouter.ai/v1.
//
// The provider mirrors the project's existing Gemini provider: credentials
// come from the environment/config, requests are synchronous, and the model
// catalog is discovered at run time with a bounded, verified fallback.
package orcarouter

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/aflow/backend"
	"github.com/google/syzkaller/pkg/log"
)

const (
	// DefaultBaseURL is the public OrcaRouter inference API.
	DefaultBaseURL = "https://api.orcarouter.ai/v1"
	// DefaultModel is the general routing model used when the caller does not
	// pick a model. It works with any OrcaRouter API key.
	DefaultModel = "orcarouter/auto"
	// CyberUltraModel is the dedicated cyber model for security code scanning
	// and multi-step reasoning over large code bases.
	CyberUltraModel = "orca/orcacyber-ultra-1.0"
	// CyberZeroModel is the OrcaCyber-harness-driven cyber model.
	CyberZeroModel = "orca/orcacyber-zero-1.5"
	// FallbackModel is the general-purpose fallback model.
	FallbackModel = "orcarouter/fusion"

	catalogSourceLive = "live"
	catalogSourceSeed = "seed"

	defaultDiscoveryTimeout = 20 * time.Second
	// maxCatalogBytes bounds how much of a catalog response we accept.
	maxCatalogBytes = 8 << 20
	// maxCatalogModels bounds how many catalog records we accept.
	maxCatalogModels = 5000
)

// Config contains parameters for creating an OrcaRouter provider.
type Config struct {
	// APIKeys are OrcaRouter API keys (sk-orca-...). Keys are distributed
	// across clients in a round-robin fashion.
	APIKeys []string
	// ModelOverride, if set, forces a single model for every request.
	ModelOverride string
	// BaseURL overrides the inference base URL. If empty, ORCA_API_BASE_URL,
	// then ORCA_BASE_URL, then DefaultBaseURL are used.
	BaseURL string
	// HTTPClient overrides the HTTP client (used by tests).
	HTTPClient *http.Client
	// DiscoveryTimeout bounds the model catalog request.
	DiscoveryTimeout time.Duration
}

// ParseAPIKeys splits a newline-separated list of API keys.
func ParseAPIKeys(keys string) []string {
	var ret []string
	for key := range strings.Lines(keys) {
		if key = strings.TrimSpace(key); key != "" {
			ret = append(ret, key)
		}
	}
	return ret
}

// ResolveBaseURL returns the inference base URL. Explicit configuration wins,
// then ORCA_API_BASE_URL, then the shared ORCA_BASE_URL, then DefaultBaseURL.
// Remote origins must use HTTPS; plain HTTP is accepted only for loopback.
func ResolveBaseURL(explicit string) (string, error) {
	base := explicit
	if base == "" {
		base = os.Getenv("ORCA_API_BASE_URL")
	}
	if base == "" {
		base = os.Getenv("ORCA_BASE_URL")
	}
	if base == "" {
		base = DefaultBaseURL
	}
	return validateBaseURL(base)
}

func validateBaseURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid OrcaRouter API base URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("OrcaRouter API base URL must use https or loopback http: %q", raw)
	}
	if u.Scheme == "http" && !isLoopback(u.Hostname()) {
		return "", fmt.Errorf("OrcaRouter API base URL must use https unless it is loopback: %q", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" {
		return "", fmt.Errorf("invalid OrcaRouter API base URL: %q", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Provider implements backend.Provider for OrcaRouter.
type Provider struct {
	keys          []string
	nextKey       atomic.Uint64
	baseURL       string
	modelOverride string
	httpClient    *http.Client

	discoveryTimeout time.Duration
	discoveryMu      sync.Mutex
	mu               sync.Mutex
	catalogLoaded    bool
	catalogSource    string
	catalog          []string
	catalogErr       error
	models           map[string]*ModelInfo
}

// ModelInfo is the capability metadata of one catalog model.
type ModelInfo struct {
	ID                     string
	InputModalities        []string
	OutputModalities       []string
	SupportedEndpointTypes []string
	SupportedParameters    []string
	ContextLength          int
	MaxCompletionTokens    int
}

// NewProvider creates an OrcaRouter provider. It does not perform network I/O;
// the model catalog is fetched lazily and falls back to a verified seed.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if len(cfg.APIKeys) == 0 {
		return nil, errors.New("orcarouter provider requires a non-empty API key")
	}
	baseURL, err := ResolveBaseURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	timeout := cfg.DiscoveryTimeout
	if timeout == 0 {
		timeout = defaultDiscoveryTimeout
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{}
	}
	p := &Provider{
		keys:             slices.Clone(cfg.APIKeys),
		baseURL:          baseURL,
		modelOverride:    cfg.ModelOverride,
		httpClient:       client,
		discoveryTimeout: timeout,
	}
	// Start from a random key, so that short-lived providers do not all use the first key.
	p.nextKey.Store(rand.Uint64())
	return p, nil
}

// Client returns a client bound to one API key.
func (p *Provider) Client(ctx context.Context) (backend.Client, error) {
	if len(p.keys) == 0 {
		return nil, errors.New("orcarouter provider has no API key")
	}
	idx := p.nextKey.Add(1) % uint64(len(p.keys))
	return &client{p: p, apiKey: p.keys[idx]}, nil
}

// Models returns the IDs of text chat models available to this key. When live
// discovery fails, it returns the verified fallback catalog and the error that
// caused the degradation; callers can still offer the fallback models.
func (p *Provider) Models(ctx context.Context) ([]string, error) {
	p.ensureCatalog(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.catalog), p.catalogErr
}

// CatalogStatus reports whether the catalog came from live discovery or from
// the verified fallback seed.
func (p *Provider) CatalogStatus() (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	source := p.catalogSource
	if source == "" {
		source = catalogSourceSeed
	}
	return source, p.catalogErr
}

// ResolveModels returns the provider-specific fallback pool for a category.
func (p *Provider) ResolveModels(category backend.ModelCategory) []string {
	if p.modelOverride != "" {
		return []string{p.modelOverride}
	}
	var prefs []string
	switch category {
	case backend.DeepReasoningModel:
		// Security impact analysis benefits from the dedicated cyber tier.
		prefs = []string{CyberUltraModel, CyberZeroModel, DefaultModel}
	case backend.CoreModel:
		prefs = []string{DefaultModel, CyberUltraModel}
	case backend.LightweightModel:
		prefs = []string{DefaultModel, FallbackModel}
	default:
		prefs = []string{DefaultModel}
	}
	p.ensureCatalog(context.Background())
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.catalogSource != catalogSourceLive {
		return prefs
	}
	available := slices.DeleteFunc(slices.Clone(prefs), func(model string) bool {
		return !slices.Contains(p.catalog, model)
	})
	if len(available) == 0 && len(p.catalog) != 0 {
		return []string{p.catalog[0]}
	}
	return available
}

// Close releases provider resources.
func (p *Provider) Close() error {
	return nil
}

func (p *Provider) key() string {
	return p.keys[p.nextKey.Add(1)%uint64(len(p.keys))]
}

// validateModel fails closed when a live catalog proves the requested model is
// not an available text model. A degraded catalog cannot prove anything, so
// the explicitly requested model is allowed through.
func (p *Provider) validateModel(model string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.catalogSource != catalogSourceLive {
		return nil
	}
	if _, ok := p.models[model]; ok {
		return nil
	}
	return fmt.Errorf("model %q is not in the OrcaRouter text model catalog (available: %s)",
		model, describeModels(p.catalog))
}

func (p *Provider) ensureCatalog(ctx context.Context) {
	p.discoveryMu.Lock()
	defer p.discoveryMu.Unlock()
	p.mu.Lock()
	loaded := p.catalogLoaded
	p.mu.Unlock()
	if loaded {
		return
	}
	models, info, err := p.discover(ctx)
	p.mu.Lock()
	defer p.mu.Unlock()
	p.catalogLoaded = true
	p.models = info
	p.catalogErr = err
	if err != nil {
		log.Logf(1, "aflow/orcarouter: model discovery failed, using the verified fallback catalog: %v", err)
		p.catalogSource = catalogSourceSeed
		p.catalog = seedCatalog()
		return
	}
	p.catalogSource = catalogSourceLive
	p.catalog = models
}

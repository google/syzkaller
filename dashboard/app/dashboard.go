// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"os"

	"cloud.google.com/go/profiler"
	"github.com/google/syzkaller/pkg/log"
	"google.golang.org/appengine/v2"

	texporter "github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace"
	"go.opentelemetry.io/contrib/detectors/gcp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
)

// Doc on https://cloud.google.com/profiler/docs/profiling-go#using-profiler
func enableProfiling() {
	// Profiler initialization, best done as early as possible.
	if err := profiler.Start(profiler.Config{
		// Service and ServiceVersion can be automatically inferred when running
		// on App Engine.
		// ProjectID must be set if not running on GCP.
		// ProjectID: "my-project",
	}); err != nil {
		log.Logf(0, "failed to start profiler: %v", err)
	}
}

// Doc on https://cloud.google.com/trace/docs/setup/go-ot
func enableTracing() {
	// Create exporter.
	ctx := context.Background()
	projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
	exporter, err := texporter.New(texporter.WithProjectID(projectID))
	if err != nil {
		log.Fatalf("texporter.New: %v", err)
	}

	// Identify your application using resource detection
	res, err := resource.New(ctx,
		// Use the GCP resource detector to detect information about the GCP platform
		resource.WithDetectors(gcp.NewDetector()),
		// Keep the default detectors
		resource.WithTelemetrySDK(),
		// Add your own custom attributes to identify your application
		resource.WithAttributes(
			semconv.ServiceNameKey.String("my-application"),
		),
	)
	if err != nil {
		log.Fatalf("resource.New: %v", err)
	}

	// Create trace provider with the exporter.
	//
	// By default it uses AlwaysSample() which samples all traces.
	// In a production environment or high QPS setup please use
	// probabilistic sampling.
	// Example:
	//   tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.TraceIDRatioBased(0.0001)), ...)
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)
	defer tp.ForceFlush(ctx) // flushes any pending spans
	otel.SetTracerProvider(tp)

	tracer := otel.GetTracerProvider().Tracer("example.com/trace")
	err = func(ctx context.Context) error {
		ctx, span := tracer.Start(ctx, "foo")
		defer span.End()

		// Do some work.

		return nil
	}(ctx)
}

func main() {
	//enableProfiling()
	enableTracing()
	installConfig(mainConfig)
	appengine.Main()
}

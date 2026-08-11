// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Orchestrator coordinates kernel builds, bisections, and manager deployments on Kubernetes.
type Orchestrator struct {
	client    kubernetes.Interface
	namespace string
}

// BuildConfig holds parameters for launching a kernel build job.
type BuildConfig struct {
	Repo            string
	Branch          string
	Commit          string
	ConfigPath      string
	GCSBucket       string
	GCSEndpoint     string
	DashboardAddr   string
	DashboardClient string
	DashboardKey    string
	ManagerName     string
	Tag             string
}

// BisectConfig holds parameters for launching a kernel bisection job.
type BisectConfig struct {
	ConfigPath string
	CrashPath  string
}

// NewOrchestrator creates a new Orchestrator instance with the appropriate cluster config.
func NewOrchestrator(kubeconfigPath, namespace string) (*Orchestrator, error) {
	if namespace == "" {
		namespace = "syzkube"
	}
	config, err := getKubeConfig(kubeconfigPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &Orchestrator{
		client:    clientset,
		namespace: namespace,
	}, nil
}

func getKubeConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	defaultKubeconfig := filepath.Join(home, ".kube", "config")
	if _, err := os.Stat(defaultKubeconfig); err == nil {
		return clientcmd.BuildConfigFromFlags("", defaultKubeconfig)
	}
	return nil, fmt.Errorf("no in-cluster config or kubeconfig found")
}

// ScheduleBuildJob creates and submits a Kubernetes Job to compile a kernel and upload artifacts.
func (o *Orchestrator) ScheduleBuildJob(ctx context.Context, cfg BuildConfig) (*batchv1.Job, error) {
	hashInput := fmt.Sprintf("%s-%s-%s-%s", cfg.Repo, cfg.Branch, cfg.Commit, cfg.ConfigPath)
	hash := sha256.Sum256([]byte(hashInput))
	jobName := fmt.Sprintf("syz-build-%s", hex.EncodeToString(hash[:])[:8])

	args := []string{
		fmt.Sprintf("-repo=%s", cfg.Repo),
		fmt.Sprintf("-branch=%s", cfg.Branch),
		fmt.Sprintf("-config=%s", cfg.ConfigPath),
	}
	if cfg.Commit != "" {
		args = append(args, fmt.Sprintf("-commit=%s", cfg.Commit))
	}
	if cfg.GCSBucket != "" {
		args = append(args, fmt.Sprintf("-gcs-bucket=%s", cfg.GCSBucket))
	}
	if cfg.GCSEndpoint != "" {
		args = append(args, fmt.Sprintf("-gcs-endpoint=%s", cfg.GCSEndpoint))
	}
	if cfg.DashboardAddr != "" {
		args = append(args, fmt.Sprintf("-dashboard-addr=%s", cfg.DashboardAddr))
	}
	if cfg.DashboardClient != "" {
		args = append(args, fmt.Sprintf("-dashboard-client=%s", cfg.DashboardClient))
	}
	if cfg.DashboardKey != "" {
		args = append(args, fmt.Sprintf("-dashboard-key=%s", cfg.DashboardKey))
	}
	if cfg.ManagerName != "" {
		args = append(args, fmt.Sprintf("-manager-name=%s", cfg.ManagerName))
	}
	if cfg.Tag != "" {
		args = append(args, fmt.Sprintf("-tag=%s", cfg.Tag))
	}

	backoffLimit := int32(0)
	hostPathDir := corev1.HostPathDirectory
	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: o.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "syz-build",
				"app.kubernetes.io/component": "kernel-builder",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:       "builder",
							Image:      "gcr.io/syzkaller/env",
							WorkingDir: "/syzkaller",
							Command: []string{
								"sh", "-c",
								"apt-get update && apt-get install -y xz-utils ccache && " +
									"ln -sf /usr/bin/ccache /usr/local/bin/gcc && " +
									"ln -sf /usr/bin/ccache /usr/local/bin/g++ && " +
									"ln -sf /usr/bin/ccache /usr/local/bin/clang && " +
									"ln -sf /usr/bin/ccache /usr/local/bin/clang++ && " +
									"go run /syzkaller/tools/syz-kube/build-wrapper/main.go \"$@\" && ccache -s",
								"--",
							},
							Args: args,
							Env: []corev1.EnvVar{
								{
									Name:  "CCACHE_DIR",
									Value: "/ccache",
								},
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "workspace",
									MountPath: "/syzkaller",
								},
								{
									Name:      "ccache-volume",
									MountPath: "/ccache",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "workspace",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/syzkaller",
									Type: &hostPathDir,
								},
							},
						},
						{
							Name: "ccache-volume",
							VolumeSource: corev1.VolumeSource{
								PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{
									ClaimName: "ccache-pvc",
								},
							},
						},
					},
				},
			},
		},
	}

	return o.client.BatchV1().Jobs(o.namespace).Create(ctx, job, metav1.CreateOptions{})
}

// ScheduleBisectionJob creates and submits an ephemeral bisection job to Kubernetes.
func (o *Orchestrator) ScheduleBisectionJob(ctx context.Context, cfg BisectConfig) (*batchv1.Job, error) {
	hashInput := fmt.Sprintf("%s-%s-%d", cfg.ConfigPath, cfg.CrashPath, time.Now().UnixNano())
	hash := sha256.Sum256([]byte(hashInput))
	jobName := fmt.Sprintf("syz-bisect-%s", hex.EncodeToString(hash[:])[:8])

	backoffLimit := int32(0)
	privileged := true
	hostPathDir := corev1.HostPathDirectory
	hostPathFile := corev1.HostPathFile

	bisectCmd := fmt.Sprintf(
		"set -e\n"+
			"export DEBIAN_FRONTEND=noninteractive\n"+
			"apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 git\n"+
			"git config --global --add safe.directory '*'\n\n"+
			"echo \"Cloning syzkaller repository...\"\n"+
			"mkdir -p /go/src/github.com/google\n"+
			"git clone https://github.com/google/syzkaller.git /go/src/github.com/google/syzkaller\n"+
			"cd /go/src/github.com/google/syzkaller\n\n"+
			"echo \"Building syz-bisect and target binaries...\"\n"+
			"make bisect target\n\n"+
			"echo \"Starting bisection job...\"\n"+
			"./bin/syz-bisect -config %s -crash %s\n",
		cfg.ConfigPath, cfg.CrashPath,
	)

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: o.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "syz-bisect",
				"app.kubernetes.io/component": "bisection-runner",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:    "bisect",
							Image:   "gcr.io/syzkaller/env",
							Command: []string{"sh", "-c", bisectCmd},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "dev-kvm",
									MountPath: "/dev/kvm",
								},
								{
									Name:      "git-cache",
									MountPath: "/git-cache",
								},
								{
									Name:      "disk-image",
									MountPath: "/disk.raw",
								},
								{
									Name:      "config-dir",
									MountPath: "/config",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "dev-kvm",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/dev/kvm",
								},
							},
						},
						{
							Name: "git-cache",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/projects/linux",
								},
							},
						},
						{
							Name: "disk-image",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/projects/disk.raw",
									Type: &hostPathFile,
								},
							},
						},
						{
							Name: "config-dir",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/projects/syzkaller",
									Type: &hostPathDir,
								},
							},
						},
					},
				},
			},
		},
	}

	return o.client.BatchV1().Jobs(o.namespace).Create(ctx, job, metav1.CreateOptions{})
}

// ListJobs returns all active or completed jobs managed in the namespace.
func (o *Orchestrator) ListJobs(ctx context.Context, labelSelector string) (*batchv1.JobList, error) {
	opts := metav1.ListOptions{}
	if labelSelector != "" {
		opts.LabelSelector = labelSelector
	}
	return o.client.BatchV1().Jobs(o.namespace).List(ctx, opts)
}

// DeleteJob deletes a job by name.
func (o *Orchestrator) DeleteJob(ctx context.Context, name string) error {
	propagationPolicy := metav1.DeletePropagationBackground
	return o.client.BatchV1().Jobs(o.namespace).Delete(ctx, name, metav1.DeleteOptions{
		PropagationPolicy: &propagationPolicy,
	})
}

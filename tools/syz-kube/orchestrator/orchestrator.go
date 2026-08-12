// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/matrix"
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

// LoopConfig defines parameters for the continuous automated fuzzing loop.
type LoopConfig struct {
	MatrixPath      string
	PlatformPrefix  string
	Compiler        string
	FuzzDuration    time.Duration
	Repo            string
	Branch          string
	Commit          string
	GCSBucket       string
	GCSEndpoint     string
	DashboardAddr   string
	DashboardClient string
	DashboardKey    string
	ManagerName     string
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
	hashInput := fmt.Sprintf("%s-%s-%s-%s-%s", cfg.Repo, cfg.Branch, cfg.Commit, cfg.ConfigPath, cfg.Tag)
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
									Path: "/projects/syzkaller",
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

// WaitForJob blocks until the specified Job succeeds, fails, or the timeout expires.
func (o *Orchestrator) WaitForJob(ctx context.Context, jobName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		job, err := o.client.BatchV1().Jobs(o.namespace).Get(ctx, jobName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		if job.Status.Succeeded > 0 {
			return nil
		}
		if job.Status.Failed > 0 {
			return fmt.Errorf("job %s failed", jobName)
		}
		time.Sleep(5 * time.Second)
	}
	return fmt.Errorf("timed out waiting for job %s to finish", jobName)
}

// UpdateManagerConfigAndRestart updates the syz-manager ConfigMap with new execution parameters and restarts the pod.
func (o *Orchestrator) UpdateManagerConfigAndRestart(ctx context.Context, tag, cmdline, qemuArgs string) error {
	configMapName := "syz-manager-config"
	cm, err := o.client.CoreV1().ConfigMaps(o.namespace).Get(ctx, configMapName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get configmap %s: %w", configMapName, err)
	}

	type ManagerVMConfig struct {
		Count    int    `json:"count"`
		Kernel   string `json:"kernel"`
		CPU      int    `json:"cpu"`
		Mem      int    `json:"mem"`
		QemuArgs string `json:"qemu_args"`
		Cmdline  string `json:"cmdline"`
	}

	type ManagerConfigJSON struct {
		Name            string          `json:"name"`
		Target          string          `json:"target"`
		HTTP            string          `json:"http"`
		Workdir         string          `json:"workdir"`
		Syzkaller       string          `json:"syzkaller"`
		KernelObj       string          `json:"kernel_obj"`
		Image           string          `json:"image"`
		SSHKey          string          `json:"sshkey"`
		Sandbox         string          `json:"sandbox"`
		Type            string          `json:"type"`
		Procs           int             `json:"procs"`
		Cover           bool            `json:"cover"`
		DashboardClient string          `json:"dashboard_client"`
		DashboardAddr   string          `json:"dashboard_addr"`
		DashboardKey    string          `json:"dashboard_key"`
		Tag             string          `json:"tag"`
		VM              ManagerVMConfig `json:"vm"`
	}

	var mcfg ManagerConfigJSON
	if raw, ok := cm.Data["manager.cfg"]; ok {
		_ = json.Unmarshal([]byte(raw), &mcfg)
	}

	// Update targeted fields.
	mcfg.Name = "syz-k8s-manager"
	mcfg.Target = "linux/amd64"
	mcfg.HTTP = "0.0.0.0:50002"
	mcfg.Workdir = "/workdir"
	mcfg.Syzkaller = "/syzkaller"
	mcfg.KernelObj = "/syzkaller/assets"
	mcfg.Image = "/disk.raw"
	mcfg.SSHKey = "/syzkaller/assets/id_rsa"
	mcfg.Sandbox = "none"
	mcfg.Type = "qemu"
	mcfg.Procs = 2
	mcfg.Cover = true
	mcfg.DashboardClient = "local_ui_client"
	mcfg.DashboardAddr = "http://syz-dashboard.syzkube.svc.cluster.local:8080"
	mcfg.DashboardKey = "localuipasswordlocaluipasswordlocaluipassword"
	mcfg.Tag = tag
	mcfg.VM.Count = 2
	mcfg.VM.Kernel = "/syzkaller/assets/bzImage"
	mcfg.VM.CPU = 1
	mcfg.VM.Mem = 2048
	mcfg.VM.Cmdline = cmdline
	mcfg.VM.QemuArgs = qemuArgs

	updatedBytes, err := json.MarshalIndent(mcfg, "", "  ")
	if err != nil {
		return err
	}

	cm.Data["manager.cfg"] = string(updatedBytes)
	if _, err := o.client.CoreV1().ConfigMaps(o.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update configmap: %w", err)
	}

	// Restart manager pod so new configuration and assets take effect.
	_ = o.client.CoreV1().Pods(o.namespace).Delete(ctx, "syz-manager-0", metav1.DeleteOptions{})
	return nil
}

// ScheduleCoverageAggregationJob launches a job to run coverage aggregation into Spanner.
func (o *Orchestrator) ScheduleCoverageAggregationJob(ctx context.Context, tag string) (*batchv1.Job, error) {
	jobName := fmt.Sprintf("coverage-aggregator-%d", time.Now().UnixNano()/1e6)
	backoffLimit := int32(0)
	hostPathDir := corev1.HostPathDirectory

	cmd := "export SPANNER_EMULATOR_HOST=cloud-spanner-emulator.syzkube.svc.cluster.local:9010\n" +
		"export STORAGE_EMULATOR_HOST=http://fake-gcs-server.syzkube.svc.cluster.local:4443\n" +
		"echo \"Running coverage aggregation for tag: " + tag + "\"\n" +
		"go run /syzkaller/tools/syz-covermerger " +
		"-workdir=/tmp/cover-workdir " +
		"-repo=/projects/linux " +
		"-commit=HEAD " +
		"-namespace=upstream\n"

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{
			Name:      jobName,
			Namespace: o.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/name":      "coverage-aggregator",
				"app.kubernetes.io/component": "aggregator",
			},
		},
		Spec: batchv1.JobSpec{
			BackoffLimit: &backoffLimit,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					RestartPolicy: corev1.RestartPolicyNever,
					Containers: []corev1.Container{
						{
							Name:       "aggregator",
							Image:      "gcr.io/syzkaller/env",
							WorkingDir: "/syzkaller",
							Command:    []string{"sh", "-c", cmd},
							VolumeMounts: []corev1.VolumeMount{
								{
									Name:      "workspace",
									MountPath: "/syzkaller",
								},
								{
									Name:      "git-cache",
									MountPath: "/projects/linux",
								},
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "workspace",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/projects/syzkaller",
									Type: &hostPathDir,
								},
							},
						},
						{
							Name: "git-cache",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: "/projects/linux",
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

// RunFuzzLoop runs the continuous hourly fuzzing loop.
func (o *Orchestrator) RunFuzzLoop(ctx context.Context, cfg LoopConfig) error {
	m, err := matrix.LoadMatrix(cfg.MatrixPath)
	if err != nil {
		return fmt.Errorf("failed to load matrix: %w", err)
	}

	baseConfigPath := m.Base.Config
	if baseConfigPath == "" {
		baseConfigPath = "dashboard/config/linux/upstream-apparmor-kasan.config"
	}
	baseData, err := os.ReadFile(baseConfigPath)
	if err != nil && !filepath.IsAbs(baseConfigPath) {
		baseData, err = os.ReadFile(filepath.Join("/syzkaller", baseConfigPath))
	}
	if err != nil {
		return fmt.Errorf("failed to read base config (%s): %w", baseConfigPath, err)
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	filter := matrix.Filter{
		PlatformPrefix: cfg.PlatformPrefix,
		Compiler:       cfg.Compiler,
	}

	iteration := 1
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		log.Printf("=== starting fuzz loop iteration #%d ===", iteration)

		// 1. Sample a random configuration matching the requested filter.
		sampled, err := m.SampleFiltered(rng, filter)
		if err != nil {
			log.Printf("error sampling matrix config: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("sampled config: tag=%s, platform=%s, features=%v",
			sampled.Tag, sampled.Platform, sampled.Features)

		// 2. Generate temporary .config file in shared workspace directory.
		genDir := "/syzkaller/generated_configs"
		if _, err := os.Stat("/syzkaller"); os.IsNotExist(err) {
			genDir = "generated_configs"
		}
		tmpDir := filepath.Join(genDir, sampled.Tag)
		_ = os.MkdirAll(tmpDir, 0755)
		mergedConfig, err := m.MergeKconfig(baseData, sampled)
		if err != nil {
			log.Printf("error merging kconfig: %v", err)
			continue
		}
		configPath := filepath.Join(tmpDir, "kernel.config")
		if err := os.WriteFile(configPath, mergedConfig, 0644); err != nil {
			log.Printf("error writing generated config: %v", err)
			continue
		}

		// 3. Schedule kernel compilation job.
		log.Printf("scheduling kernel build job for tag %s...", sampled.Tag)
		buildJob, err := o.ScheduleBuildJob(ctx, BuildConfig{
			Repo:            cfg.Repo,
			Branch:          cfg.Branch,
			Commit:          cfg.Commit,
			ConfigPath:      configPath,
			GCSBucket:       cfg.GCSBucket,
			GCSEndpoint:     cfg.GCSEndpoint,
			DashboardAddr:   cfg.DashboardAddr,
			DashboardClient: cfg.DashboardClient,
			DashboardKey:    cfg.DashboardKey,
			ManagerName:     cfg.ManagerName,
			Tag:             sampled.Tag,
		})
		if err != nil {
			log.Printf("error scheduling build job: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("waiting for build job %s to complete...", buildJob.Name)
		if err := o.WaitForJob(ctx, buildJob.Name, 45*time.Minute); err != nil {
			log.Printf("build job %s failed: %v", buildJob.Name, err)
			time.Sleep(10 * time.Second)
			continue
		}
		log.Printf("build job %s succeeded! artifacts uploaded and build registered", buildJob.Name)

		// 4. Update manager configuration and restart fuzzing pod.
		log.Printf("updating syz-manager with tag %s and restarting fuzzing...", sampled.Tag)
		if err := o.UpdateManagerConfigAndRestart(ctx, sampled.Tag, sampled.Cmdline, sampled.QemuArgs); err != nil {
			log.Printf("failed to update manager config: %v", err)
		}

		// 5. Fuzz for requested duration (e.g. 1 hour).
		log.Printf("fuzzing session in progress for %v...", cfg.FuzzDuration)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(cfg.FuzzDuration):
		}

		// 6. Trigger coverage aggregation.
		log.Printf("fuzzing session finished. triggering coverage aggregation...")
		if _, err := o.ScheduleCoverageAggregationJob(ctx, sampled.Tag); err != nil {
			log.Printf("failed to schedule coverage aggregation job: %v", err)
		}

		iteration++
	}
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

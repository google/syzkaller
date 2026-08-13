// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"sync"
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
	Compiler        string
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
	NumManagers     int
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
	if cfg.Compiler != "" {
		args = append(args, fmt.Sprintf("-compiler=%s", cfg.Compiler))
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

// UpdateManagerConfigAndRestart updates the syz-manager ConfigMap for the given worker index and restarts the pod.
func (o *Orchestrator) UpdateManagerConfigAndRestart(
	ctx context.Context, workerIndex int, tag, cmdline, qemuArgs string,
) error {
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

	// Update targeted fields. Base name is dynamically overridden per-pod by $HOSTNAME at startup.
	mcfg.Name = "syz-k8s-manager"
	mcfg.Target = "linux/amd64"
	mcfg.HTTP = "0.0.0.0:50002"
	mcfg.Workdir = "/workdir"
	mcfg.Syzkaller = "/syzkaller"

	kernelObj := fmt.Sprintf("/syzkaller/assets/%s", tag)
	kernelImage := fmt.Sprintf("/syzkaller/assets/%s/bzImage", tag)
	if _, err := os.Stat(fmt.Sprintf("/syzkaller/assets/%s/bzImage", tag)); os.IsNotExist(err) {
		kernelObj = "/syzkaller/assets"
		kernelImage = "/syzkaller/assets/bzImage"
	}
	mcfg.KernelObj = kernelObj
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
	mcfg.VM.Kernel = kernelImage
	mcfg.VM.CPU = 1
	mcfg.VM.Mem = 2048
	mcfg.VM.Cmdline = cmdline
	mcfg.VM.QemuArgs = qemuArgs

	updatedBytes, err := json.MarshalIndent(mcfg, "", "  ")
	if err != nil {
		return err
	}

	cm.Data = map[string]string{
		"manager.cfg": string(updatedBytes),
	}

	if _, err := o.client.CoreV1().ConfigMaps(o.namespace).Update(ctx, cm, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("failed to update configmap: %w", err)
	}

	// Restart specific manager pod so new configuration and assets take effect.
	podName := fmt.Sprintf("syz-manager-%d", workerIndex)
	log.Printf("restarting pod %s...", podName)
	_ = o.client.CoreV1().Pods(o.namespace).Delete(ctx, podName, metav1.DeleteOptions{})
	return nil
}

// ScheduleCoverageAggregationJob launches a job to run coverage aggregation into Spanner.
func (o *Orchestrator) ScheduleCoverageAggregationJob(ctx context.Context, tag string) (*batchv1.Job, error) {
	jobName := fmt.Sprintf("coverage-aggregator-%d", time.Now().UnixNano()/1e6)
	backoffLimit := int32(0)
	hostPathDir := corev1.HostPathDirectory

	today := time.Now().UTC().Format("2006-01-02")
	cmd := "export SPANNER_EMULATOR_HOST=cloud-spanner-emulator.syzkube.svc.cluster.local:9010\n" +
		"export STORAGE_EMULATOR_HOST=http://fake-gcs-server.syzkube.svc.cluster.local:4443\n" +
		"export GOOGLE_CLOUD_PROJECT=syzkaller\n" +
		"export SYZ_DISABLE_SANDBOXING=yes\n" +
		"echo \"Running coverage aggregation for tag: " + tag + "\"\n" +
		"go run /syzkaller/tools/syz-covermerger " +
		"-workdir=/tmp/cover-workdir " +
		"-repo=/projects/linux " +
		"-commit=HEAD " +
		"-namespace=upstream " +
		"-date-to=" + today + " " +
		"-duration=30 " +
		"-raw-coverage-dir=/syzkaller/export/coverage " +
		"-dashboard-client-name=coverage-merger " +
		"-dashboard-key=coveragemergerkey1234567890123456 " +
		"-to-dashapi=http://syz-dashboard.syzkube.svc.cluster.local:8080\n"

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

// RunFuzzLoop runs continuous fuzzing with the specified number of parallel managers.
func (o *Orchestrator) RunFuzzLoop(ctx context.Context, cfg LoopConfig) error {
	numManagers := cfg.NumManagers
	if numManagers <= 0 {
		numManagers = 5
	}

	log.Printf("starting continuous fuzzing orchestrator with %d parallel managers...", numManagers)

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

	platformPrefix := cfg.PlatformPrefix
	if platformPrefix == "" || platformPrefix == "qemu" {
		platformPrefix = "qemu_x86_64"
	}
	compiler := cfg.Compiler
	if compiler == "" {
		compiler = "clang"
	}
	filter := matrix.Filter{
		PlatformPrefix: platformPrefix,
		Compiler:       compiler,
	}

	var wg sync.WaitGroup
	for workerIdx := range numManagers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			o.runManagerWorkerLoop(ctx, idx, m, baseData, filter, cfg)
		}(workerIdx)
	}

	wg.Wait()
	return nil
}

func (o *Orchestrator) runManagerWorkerLoop(
	ctx context.Context,
	workerIndex int,
	m *matrix.Matrix,
	baseData []byte,
	filter matrix.Filter,
	cfg LoopConfig,
) {
	// Stagger worker starts to prevent build resource collision.
	staggerDelay := time.Duration(workerIndex) * 90 * time.Second
	if staggerDelay > 0 {
		log.Printf("[worker-%d] waiting %v before first iteration to stagger initial builds...",
			workerIndex, staggerDelay)
		select {
		case <-ctx.Done():
			return
		case <-time.After(staggerDelay):
		}
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano() + int64(workerIndex*1000)))
	iteration := 1
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[worker-%d] === starting fuzz loop iteration #%d ===", workerIndex, iteration)

		// 1. Sample a random configuration matching the requested filter.
		sampled, err := m.SampleFiltered(rng, filter)
		if err != nil {
			log.Printf("[worker-%d] error sampling matrix config: %v", workerIndex, err)
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("[worker-%d] sampled config: tag=%s, platform=%s, features=%v",
			workerIndex, sampled.Tag, sampled.Platform, sampled.Features)

		// 2. Generate temporary .config file in shared workspace directory.
		genDir := "/syzkaller/generated_configs"
		if _, err := os.Stat("/syzkaller"); os.IsNotExist(err) {
			genDir = "generated_configs"
		}
		tmpDir := filepath.Join(genDir, sampled.Tag)
		_ = os.MkdirAll(tmpDir, 0755)
		mergedConfig, err := m.MergeKconfig(baseData, sampled)
		if err != nil {
			log.Printf("[worker-%d] error merging kconfig: %v", workerIndex, err)
			continue
		}
		configPath := filepath.Join(tmpDir, "kernel.config")
		if err := os.WriteFile(configPath, mergedConfig, 0644); err != nil {
			log.Printf("[worker-%d] error writing generated config: %v", workerIndex, err)
			continue
		}

		// 3. Schedule kernel compilation job.
		compilerChoice := sampled.SelectedAxes["compiler"]
		if compilerChoice == "" {
			compilerChoice = filter.Compiler
		}
		managerName := fmt.Sprintf("syz-k8s-manager-%d", workerIndex)
		log.Printf("[worker-%d] scheduling kernel build job for tag %s (compiler: %s)...",
			workerIndex, sampled.Tag, compilerChoice)
		buildJob, err := o.ScheduleBuildJob(ctx, BuildConfig{
			Repo:            cfg.Repo,
			Branch:          cfg.Branch,
			Commit:          cfg.Commit,
			ConfigPath:      configPath,
			Compiler:        compilerChoice,
			GCSBucket:       cfg.GCSBucket,
			GCSEndpoint:     cfg.GCSEndpoint,
			DashboardAddr:   cfg.DashboardAddr,
			DashboardClient: cfg.DashboardClient,
			DashboardKey:    cfg.DashboardKey,
			ManagerName:     managerName,
			Tag:             sampled.Tag,
		})
		if err != nil {
			log.Printf("[worker-%d] error scheduling build job: %v", workerIndex, err)
			time.Sleep(10 * time.Second)
			continue
		}

		log.Printf("[worker-%d] waiting for build job %s to complete...", workerIndex, buildJob.Name)
		if err := o.WaitForJob(ctx, buildJob.Name, 45*time.Minute); err != nil {
			log.Printf("[worker-%d] build job %s failed: %v", workerIndex, buildJob.Name, err)
			time.Sleep(10 * time.Second)
			continue
		}
		log.Printf("[worker-%d] build job %s succeeded! artifacts uploaded and build registered",
			workerIndex, buildJob.Name)

		// 4. Update manager configuration and restart fuzzing pod for this worker.
		log.Printf("[worker-%d] updating syz-manager-%d with tag %s and restarting fuzzing...",
			workerIndex, workerIndex, sampled.Tag)
		if err := o.UpdateManagerConfigAndRestart(
			ctx, workerIndex, sampled.Tag, sampled.Cmdline, sampled.QemuArgs,
		); err != nil {
			log.Printf("[worker-%d] failed to update manager config: %v", workerIndex, err)
		}

		// 5. Fuzz for requested duration (e.g. 1 hour).
		log.Printf("[worker-%d] fuzzing session in progress for %v...", workerIndex, cfg.FuzzDuration)
		select {
		case <-ctx.Done():
			return
		case <-time.After(cfg.FuzzDuration):
		}

		// 6. Save session coverage from syz-manager (/cover?jsonl=1) before restarting.
		log.Printf("[worker-%d] fuzzing session finished. saving session coverage (/cover?jsonl=1)...",
			workerIndex)
		if err := o.SaveSessionCoverage(ctx, workerIndex, sampled.Tag); err != nil {
			log.Printf("[worker-%d] failed to save session coverage: %v", workerIndex, err)
		}

		// 7. Trigger coverage aggregation.
		log.Printf("[worker-%d] triggering coverage aggregation...", workerIndex)
		if _, err := o.ScheduleCoverageAggregationJob(ctx, sampled.Tag); err != nil {
			log.Printf("[worker-%d] failed to schedule coverage aggregation job: %v", workerIndex, err)
		}

		iteration++
	}
}

// SaveSessionCoverage downloads raw coverage JSONL from the syz-manager HTTP API (/cover?jsonl=1)
// and stores the compressed .jsonl.gz archive in shared export storage.
func (o *Orchestrator) SaveSessionCoverage(ctx context.Context, workerIndex int, tag string) error {
	managerHost := fmt.Sprintf("syz-manager-%d.syz-manager.%s.svc.cluster.local", workerIndex, o.namespace)
	url := fmt.Sprintf("http://%s:50002/cover?jsonl=1", managerHost)
	log.Printf("[worker-%d] fetching coverage jsonl from %s for tag %s...", workerIndex, url, tag)

	reqCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		// Fallback to pod IP directly if headless DNS resolution is not ready.
		pod, podErr := o.client.CoreV1().Pods(o.namespace).Get(
			reqCtx, fmt.Sprintf("syz-manager-%d", workerIndex), metav1.GetOptions{},
		)
		if podErr == nil && pod.Status.PodIP != "" {
			fallbackURL := fmt.Sprintf("http://%s:50002/cover?jsonl=1", pod.Status.PodIP)
			fallbackReq, _ := http.NewRequestWithContext(reqCtx, http.MethodGet, fallbackURL, nil)
			resp, err = http.DefaultClient.Do(fallbackReq)
		}
	}
	if err != nil {
		return fmt.Errorf("failed to connect to manager HTTP for worker-%d: %w", workerIndex, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("manager HTTP returned %s", resp.Status)
	}

	exportDir := "/syzkaller/export/coverage"
	if _, err := os.Stat("/syzkaller"); os.IsNotExist(err) {
		exportDir = "export/coverage"
	}
	if err := os.MkdirAll(exportDir, 0755); err != nil {
		return fmt.Errorf("failed to create export dir: %w", err)
	}

	fileName := fmt.Sprintf("%s-manager-%d-%d.jsonl.gz", tag, workerIndex, time.Now().Unix())
	filePath := filepath.Join(exportDir, fileName)
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	written, err := io.Copy(gw, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to stream coverage gzip data: %w", err)
	}
	log.Printf("[worker-%d] successfully saved %d bytes of raw coverage data to %s",
		workerIndex, written, filePath)
	return nil
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

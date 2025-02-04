// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package workflow

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"sort"
	"time"

	"github.com/argoproj/argo-workflows/v3/pkg/apis/workflow/v1alpha1"
	wfclientset "github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned"
	wftypes "github.com/argoproj/argo-workflows/v3/pkg/client/clientset/versioned/typed/workflow/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	restclient "k8s.io/client-go/rest"
	"sigs.k8s.io/yaml"
)

//go:embed *.yaml
var workflowsFS embed.FS

type ArgoService struct {
	wfClient wftypes.WorkflowInterface
	template *v1alpha1.Workflow
}

func NewArgoService() (*ArgoService, error) {
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		return nil, err
	}
	namespace := "default"
	wfClient := wfclientset.NewForConfigOrDie(kubeConfig).ArgoprojV1alpha1().Workflows(namespace)
	templateData, err := workflowsFS.ReadFile("template.yaml")
	if err != nil {
		return nil, err
	}
	var wf v1alpha1.Workflow
	err = yaml.Unmarshal(templateData, &wf)
	if err != nil {
		return nil, err
	}
	return &ArgoService{
		wfClient: wfClient,
		template: &wf,
	}, nil
}

// TODO: substitute the proper (non-dev) Docker image names.
func (w *ArgoService) Start(sessionID string) error {
	workflow := w.template.DeepCopy()
	workflow.ObjectMeta.Labels = map[string]string{
		"workflow-id": sessionID,
	}
	for i, param := range workflow.Spec.Arguments.Parameters {
		if param.Name == "session-id" {
			workflow.Spec.Arguments.Parameters[i].Value = v1alpha1.AnyStringPtr(sessionID)
		}
	}
	_, err := w.wfClient.Create(context.Background(), workflow, metav1.CreateOptions{})
	return err
}

func (w *ArgoService) Status(sessionID string) (Status, []byte, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("workflow-id=%s", sessionID),
	}
	workflows, err := w.wfClient.List(context.Background(), listOptions)
	if err != nil || len(workflows.Items) == 0 {
		return StatusNotFound, nil, err
	}
	wf := workflows.Items[0]
	log := w.generateLog(wf.Status.Nodes)
	switch wf.Status.Phase {
	case v1alpha1.WorkflowRunning, v1alpha1.WorkflowPending:
		return StatusRunning, log, nil
	case v1alpha1.WorkflowSucceeded:
		return StatusFinished, log, nil
	}
	return StatusFailed, log, nil
}

func (w *ArgoService) generateLog(nodes v1alpha1.Nodes) []byte {
	var list []v1alpha1.NodeStatus
	for _, node := range nodes {
		list = append(list, node)
	}
	sort.Slice(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if !a.StartedAt.Equal(&b.StartedAt) {
			return a.StartedAt.Before(&b.StartedAt)
		}
		return a.Name < b.Name
	})
	var buf bytes.Buffer
	for i, val := range list {
		if i > 0 {
			buf.WriteString("---------\n")
		}
		fmt.Fprintf(&buf, "Name: %s\n", val.Name)
		fmt.Fprintf(&buf, "Phase: %s\n", val.Phase)
		fmt.Fprintf(&buf, "StartedAt: %s\n", val.StartedAt)
		fmt.Fprintf(&buf, "FinishedAt: %s\n", val.FinishedAt)
		fmt.Fprintf(&buf, "Input: %s\n", val.Inputs)
		fmt.Fprintf(&buf, "Output: %s\n", val.Outputs)
	}
	return buf.Bytes()
}

func (w *ArgoService) PollPeriod() time.Duration {
	return 30 * time.Second
}

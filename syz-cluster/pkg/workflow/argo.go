// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package workflow

import (
	"context"
	"embed"
	"fmt"
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

func (w *ArgoService) Status(sessionID string) (Status, error) {
	listOptions := metav1.ListOptions{
		LabelSelector: fmt.Sprintf("workflow-id=%s", sessionID),
	}
	workflows, err := w.wfClient.List(context.Background(), listOptions)
	if err != nil || len(workflows.Items) == 0 {
		return StatusNotFound, err
	}
	wf := workflows.Items[0]
	switch wf.Status.Phase {
	case v1alpha1.WorkflowRunning, v1alpha1.WorkflowPending:
		return StatusRunning, nil
	case v1alpha1.WorkflowSucceeded, v1alpha1.WorkflowFailed:
		return StatusFinished, nil
	}
	return StatusFailed, nil
}

func (w *ArgoService) PollPeriod() time.Duration {
	return time.Minute
}

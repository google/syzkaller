// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aidb

import (
	"context"
	"strings"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/uuid"
	"google.golang.org/appengine/v2"
)

func LoadWorkflows(ctx context.Context) ([]*Workflow, error) {
	client, err := dbClient(ctx)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	iter := client.Single().Query(ctx, spanner.Statement{
		SQL: `select * from Workflows`,
	})
	defer iter.Stop()
	var workflows []*Workflow
	err = spanner.SelectAll(iter, &workflows)
	return workflows, err
}

func LoadActiveWorkflows(ctx context.Context) ([]string, error) {
	workflows, err := LoadWorkflows(ctx)
	if err != nil {
		return nil, err
	}
	var active []string
	for _, flow := range workflows {
		if flow.Active {
			active = append(active, flow.Name)
		}
	}
	return active, nil
}

func UpdateWorkflows(ctx context.Context, active []string) error {
	workflows, err := LoadWorkflows(ctx)
	if err != nil {
		return err
	}
	m := make(map[string]bool)
	for _, flow := range active {
		m[flow] = true
	}
	update := false
	for _, flow := range workflows {
		active := m[flow.Name]
		delete(m, flow.Name)
		if flow.Active != active {
			update = true
			flow.Active = active
		}
	}
	for name := range m {
		update = true
		workflows = append(workflows, &Workflow{
			Name:   name,
			Type:   WorkflowType(strings.Split(name, "-")[0]),
			Active: true,
		})
	}
	if !update {
		return nil
	}
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	var mutations []*spanner.Mutation
	for _, flow := range workflows {
		mut, err := spanner.InsertOrUpdateStruct("Workflows", flow)
		if err != nil {
			return err
		}
		mutations = append(mutations, mut)
	}
	_, err = client.Apply(ctx, mutations)
	return err
}

func CreatePatchingJob(ctx context.Context, workflow string, patchingJob *PatchingJob) error {
	client, err := dbClient(ctx)
	if err != nil {
		return err
	}
	job := &Job{
		ID:       uuid.NewString(),
		Type:     WorkflowPatching,
		Workflow: workflow,
		Created:  TimeNow(ctx),
	}
	patchingJob.ID = job.ID
	insertJob, err := spanner.InsertStruct("Jobs", job)
	if err != nil {
		return err
	}
	insertPatchingJob, err := spanner.InsertStruct("PatchingJobs", patchingJob)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{insertJob, insertPatchingJob})
	return err
}

var TimeNow = func(ctx context.Context) time.Time {
	return time.Now()
}

func dbClient(ctx context.Context) (*spanner.Client, error) {
	database := "projects/" + appengine.AppID(ctx) + "/instances/syzbot/databases/ai"
	return spanner.NewClient(ctx, database)
}

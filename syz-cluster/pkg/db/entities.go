// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"time"

	"cloud.google.com/go/spanner"
)

type Series struct {
	ID          string    `spanner:"ID"`
	ExtID       string    `spanner:"ExtID"`
	AuthorName  string    `spanner:"AuthorName"`
	AuthorEmail string    `spanner:"AuthorEmail"`
	Title       string    `spanner:"Title"`
	Link        string    `spanner:"Link"`
	Version     int64     `spanner:"Version"`
	PublishedAt time.Time `spanner:"PublishedAt"`
	// TODO: we could ger rid of the field by using slightly more complicated SQL queries.
	LatestSessionID spanner.NullString `spanner:"LatestSessionID"`
	Cc              []string           `spanner:"Cc"`
}

func (s *Series) SetLatestSession(session *Session) {
	s.LatestSessionID = spanner.NullString{StringVal: session.ID, Valid: true}
}

type Patch struct {
	ID       string `spanner:"ID"`
	Seq      int64  `spanner:"Seq"`
	SeriesID string `spanner:"SeriesID"`
	Title    string `spanner:"Title"`
	Link     string `spanner:"Link"`
	BodyURI  string `spanner:"BodyURI"`
}

type Build struct {
	ID         string             `spanner:"ID"`
	TreeName   string             `spanner:"TreeName"`
	CommitHash string             `spanner:"CommitHash"`
	CommitDate time.Time          `spanner:"CommitDate"`
	SeriesID   spanner.NullString `spanner:"SeriesID"`
	Arch       string             `spanner:"Arch"`
	ConfigName string             `spanner:"ConfigName"`
	ConfigURI  string             `spanner:"ConfigURI"`
	Status     string             `spanner:"Status"`
}

func (b *Build) SetSeriesID(val string) {
	b.SeriesID = spanner.NullString{StringVal: val, Valid: true}
}

const (
	BuildFailed string = "build_failed"
	//	BuiltNotTested  string = "built"
	//	BuildTestFailed string = "tests_failed"
	BuildSuccess string = "success"
)

type Session struct {
	ID         string             `spanner:"ID"`
	SeriesID   string             `spanner:"SeriesID"`
	CreatedAt  time.Time          `spanner:"CreatedAt"`
	StartedAt  spanner.NullTime   `spanner:"StartedAt"`
	FinishedAt spanner.NullTime   `spanner:"FinishedAt"`
	SkipReason spanner.NullString `spanner:"SkipReason"`
	LogURI     string             `spanner:"LogURI"`
	Tags       []string           `spanner:"Tags"`
	// TODO: to accept more specific fuzzing assignment,
	// add Triager, BaseRepo, BaseCommit, Config fields.
}

func (s *Session) SetStartedAt(t time.Time) {
	s.StartedAt = spanner.NullTime{Time: t, Valid: true}
}

func (s *Session) SetFinishedAt(t time.Time) {
	s.FinishedAt = spanner.NullTime{Time: t, Valid: true}
}

func (s *Session) SetSkipReason(reason string) {
	s.SkipReason = spanner.NullString{StringVal: reason, Valid: true}
}

type SessionTest struct {
	SessionID      string             `spanner:"SessionID"`
	BaseBuildID    spanner.NullString `spanner:"BaseBuildID"`
	PatchedBuildID spanner.NullString `spanner:"PatchedBuildID"`
	UpdatedAt      time.Time          `spanner:"UpdatedAt"`
	TestName       string             `spanner:"TestName"`
	Result         string             `spanner:"Result"`
	LogURI         string             `spanner:"LogURI"`
}

type Finding struct {
	ID        string `spanner:"ID"`
	SessionID string `spanner:"SessionID"`
	TestName  string `spanner:"TestName"`
	Title     string `spanner:"Title"`
	ReportURI string `spanner:"ReportURI"`
	LogURI    string `spanner:"LogURI"`
}

type SessionReport struct {
	ID         string           `spanner:"ID"`
	SessionID  string           `spanner:"SessionID"`
	ReportedAt spanner.NullTime `spanner:"ReportedAt"`
	Moderation bool             `spanner:"Moderation"`
	Link       string           `spanner:"Link"`
}

func (s *SessionReport) SetReportedAt(t time.Time) {
	s.ReportedAt = spanner.NullTime{Time: t, Valid: true}
}

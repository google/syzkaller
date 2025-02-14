CREATE TABLE Series (
    ID STRING(36) NOT NULL, -- UUID
    ExtID STRING(128) NOT NULL, -- For LKML, it's a message ID of the series.
    AuthorName STRING(512) NOT NULL,
    AuthorEmail STRING(512) NOT NULL,
    Title STRING(512) NOT NULL,
    Version INT64 NOT NULL,
    Link STRING(512) NOT NULL,
    PublishedAt TIMESTAMP NOT NULL,
    LatestSessionID STRING(36),
    Cc ARRAY<STRING(256)>,
) PRIMARY KEY (ID);

CREATE INDEX SeriesByPublishedAt ON Series (PublishedAt);
CREATE UNIQUE INDEX SeriesByExtID ON Series (ExtID);

CREATE TABLE Patches (
    ID STRING(36) NOT NULL, -- UUID
    SeriesID STRING(36) NOT NULL,
    Seq INT64 NOT NULL,
    Title STRING(512) NOT NULL,
    Link STRING(512) NOT NULL,
    BodyURI STRING(512) NOT NULL, -- These might be too big to store directly in Spanner.
    CONSTRAINT FK_SeriesPatches FOREIGN KEY (SeriesID) REFERENCES Series (ID),
) PRIMARY KEY(ID);

CREATE INDEX PatchesBySeriesAndSeq ON Patches (SeriesID, Seq);

CREATE TABLE Builds (
    ID STRING(36) NOT NULL, -- UUID
    TreeName STRING(128) NOT NULL,
    CommitHash STRING(256) NOT NULL,
    CommitDate TIMESTAMP NOT NULL,
    SeriesID STRING(36), -- NULL if no series were applied to the tree.
    Arch STRING(128) NOT NULL,
    ConfigName STRING(256) NOT NULL, -- E.g. subsystem-specific build configuration names. Known to the builders.
    ConfigURI STRING(512) NOT NULL, -- The config actually used during the build.
    Status STRING(128) NOT NULL,
    CONSTRAINT FK_Series FOREIGN KEY (SeriesID) REFERENCES Series (ID),
    CONSTRAINT StatusEnum CHECK (Status IN ('build_failed', 'built', 'tests_failed', 'success')),
) PRIMARY KEY(ID);

-- It does not cover all fields that will be requested, but it should be discriminative enough.
CREATE INDEX LastSuccessfulBuild ON Builds (TreeName, SeriesID, CommitDate DESC);

/*
  There may be multiple sessions per a single series, e.g. if
  1) We happened to re-deploy the new version when the previous was being fuzzed.
  2) We want to run bechmarks: some sessions will correspond solely to them.
*/
CREATE TABLE Sessions (
    ID STRING(36) NOT NULL, -- UUID
    SeriesID STRING(36) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL,
    StartedAt TIMESTAMP,
    FinishedAt TIMESTAMP,
    SkipReason STRING(1024),
    LogURI STRING(512) NOT NULL,
    Tags ARRAY<STRING(256)>,
    CONSTRAINT FK_SeriesSessions FOREIGN KEY (SeriesID) REFERENCES Series (ID),
) PRIMARY KEY(ID);

ALTER TABLE Series ADD CONSTRAINT FK_SeriesLatestSession FOREIGN KEY (LatestSessionID) REFERENCES Sessions (ID);
CREATE INDEX SessionsByFinishedAt ON Sessions (FinishedAt);

-- Individual tests/steps completed within a session.
CREATE TABLE SessionTests (
    SessionID STRING(36) NOT NULL, -- UUID
    TestName STRING(256) NOT NULL,
    UpdatedAt TIMESTAMP NOT NULL,
    Result STRING(36) NOT NULL,
    BaseBuildID STRING(36),
    PatchedBuildID STRING(36),
    LogURI STRING(256) NOT NULL,
    CONSTRAINT FK_SessionResults FOREIGN KEY (SessionID) REFERENCES Sessions (ID),
    CONSTRAINT ResultEnum CHECK (Result IN ('passed', 'failed', 'error', 'running')),
    CONSTRAINT FK_BaseBuild FOREIGN KEY (BaseBuildID) REFERENCES Builds (ID),
    CONSTRAINT FK_PatchedBuild FOREIGN KEY (PatchedBuildID) REFERENCES Builds (ID),
) PRIMARY KEY(SessionID, TestName);

/*
  Findings are build/boot errors or crashes found during processing the patch series.
  One could have used (SessionID, TestName, Title) as a key, but that becomes very inconvenient
  if the Finding is to be referenced from multiple places.
*/
CREATE TABLE Findings (
    ID STRING(36) NOT NULL, -- UUID
    SessionID STRING(36) NOT NULL,
    TestName STRING(256) NOT NULL,
    Title STRING(256) NOT NULL,
    ReportURI STRING(256) NOT NULL,
    LogURI STRING(256) NOT NULL,
    CONSTRAINT FK_SessionCrashes FOREIGN KEY (SessionID) REFERENCES Sessions (ID),
    CONSTRAINT FK_TestCrashes FOREIGN KEY (SessionID, TestName) REFERENCES SessionTests (SessionID, TestName),
) PRIMARY KEY (ID);

CREATE UNIQUE INDEX NoDupFindings ON Findings(SessionID, TestName, Title);

-- Session's bug reports.
CREATE TABLE SessionReports (
    ID STRING(36) NOT NULL, -- UUID??
    SessionID STRING(36) NOT NULL, -- UUID
    ReportedAt TIMESTAMP,
    Moderation BOOL,
    Link STRING(256),
    CONSTRAINT FK_SessionReports FOREIGN KEY (SessionID) REFERENCES Sessions (ID),
) PRIMARY KEY(ID);

CREATE UNIQUE INDEX NoDupSessionReports ON SessionReports(SessionID, Moderation);
CREATE INDEX SessionReportsByStatus ON SessionReports (Moderation, ReportedAt);

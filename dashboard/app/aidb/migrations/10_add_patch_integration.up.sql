ALTER TABLE Jobs ADD COLUMN ParentJobID STRING(36);
ALTER TABLE Jobs ADD COLUMN Version INT64;
ALTER TABLE Jobs ADD CONSTRAINT FK_Jobs_ParentJob FOREIGN KEY (ParentJobID) REFERENCES Jobs (ID);

CREATE TABLE JobReporting (
    ID           STRING(36) NOT NULL,
    JobID        STRING(36) NOT NULL,
    Stage        STRING(255) NOT NULL,
    Source       STRING(255) NOT NULL,
    ReportedAt   TIMESTAMP,
    UpstreamedAt TIMESTAMP,
    ExtID        STRING(255),
    CreatedAt    TIMESTAMP NOT NULL,
    CONSTRAINT FK_JobReporting_Job FOREIGN KEY (JobID) REFERENCES Jobs (ID),
) PRIMARY KEY (ID);

CREATE UNIQUE INDEX JobReportingByExtID ON JobReporting(ExtID) WHERE ExtID IS NOT NULL;
CREATE UNIQUE INDEX JobReportingByJobStage ON JobReporting(JobID, Stage);

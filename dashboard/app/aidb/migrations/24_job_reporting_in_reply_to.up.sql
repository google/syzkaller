DROP INDEX JobReportingByJobStage;
ALTER TABLE JobReporting ADD COLUMN InReplyTo STRING(1000) NOT NULL DEFAULT ("");
CREATE UNIQUE INDEX JobReportingByJobStage ON JobReporting(JobID, Stage, InReplyTo);

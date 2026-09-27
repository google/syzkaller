DROP INDEX JobReportingByJobStage;
ALTER TABLE JobReporting DROP COLUMN InReplyTo;
CREATE UNIQUE INDEX JobReportingByJobStage ON JobReporting(JobID, Stage);

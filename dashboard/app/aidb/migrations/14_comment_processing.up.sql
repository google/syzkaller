ALTER TABLE JobComments ADD COLUMN Processed BOOL DEFAULT (false);
CREATE INDEX JobCommentsForIteration ON JobComments(Processed, ReportingID, Date);
ALTER TABLE Jobs ADD COLUMN ParentReportingID STRING(36);
ALTER TABLE Jobs DROP CONSTRAINT FK_Jobs_ParentJob;
ALTER TABLE Jobs DROP COLUMN ParentJobID;
ALTER TABLE JobReporting ADD COLUMN Version INT64 DEFAULT (1);
ALTER TABLE Jobs DROP COLUMN Version;

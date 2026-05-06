DROP INDEX idx_journal_msg_ext_id;
ALTER TABLE Journal DROP CONSTRAINT FK_Journal_Reporting;
ALTER TABLE Journal DROP COLUMN SourceExtID;
ALTER TABLE Journal DROP COLUMN Source;
ALTER TABLE Journal DROP COLUMN ReportingID;

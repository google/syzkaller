ALTER TABLE Jobs ADD COLUMN ExternalBugID STRING(1000);
CREATE INDEX JobExternalBugID ON Jobs(Namespace, ExternalBugID, Created DESC);

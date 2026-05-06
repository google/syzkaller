ALTER TABLE BaseFindings ADD COLUMN CommitDate TIMESTAMP;
CREATE INDEX BaseFindingsByConfigArchTitleDate ON BaseFindings(Config, Arch, Title, CommitDate);

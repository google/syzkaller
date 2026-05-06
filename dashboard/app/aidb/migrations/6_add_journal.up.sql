CREATE TABLE Journal (
	ID			STRING(36) NOT NULL,
	JobID			STRING(36),
	Date			TIMESTAMP NOT NULL,
	User			STRING(1000),
	Action			STRING(256),
	Details			JSON,
	CONSTRAINT FK_Journal_Job FOREIGN KEY (JobID) REFERENCES Jobs (ID),
) PRIMARY KEY (ID);

CREATE INDEX Journal_JobActionDate ON Journal(JobID, Action, Date DESC);

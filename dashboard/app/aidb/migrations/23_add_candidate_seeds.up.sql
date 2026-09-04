CREATE TABLE CandidateSeeds (
	JobID		STRING(36) NOT NULL,
	ID		STRING(36) NOT NULL,
	Namespace	STRING(1000) NOT NULL,
	TargetOS	STRING(100) NOT NULL,
	TargetArch	STRING(100) NOT NULL,
	CreatedAt	TIMESTAMP NOT NULL,
	Prog		BYTES(MAX) NOT NULL,

	CONSTRAINT FK_CandidateSeedJob FOREIGN KEY (JobID) REFERENCES Jobs (ID),
) PRIMARY KEY (JobID, ID);

CREATE INDEX CandidateSeedsByTarget ON CandidateSeeds (Namespace, TargetOS, TargetArch, CreatedAt, ID);

CREATE TABLE ClientSeedCursors (
	Namespace	STRING(1000) NOT NULL,
	Client		STRING(1000) NOT NULL,
	LastTriagedTime	TIMESTAMP NOT NULL,
	LastTriagedID	STRING(36) NOT NULL,
) PRIMARY KEY (Namespace, Client);

ALTER TABLE TrajectorySpans ADD COLUMN Artifacts JSON;

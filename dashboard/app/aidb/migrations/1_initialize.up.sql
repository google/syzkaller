CREATE TABLE Workflows (
	Name		STRING(1000) NOT NULL,
	Type		STRING(1000) NOT NULL,
	Active		BOOL NOT NULL,

	CONSTRAINT TypeEnum CHECK (Type IN ('patching')),
) PRIMARY KEY (Name);

CREATE TABLE Jobs (
	ID		STRING(36) NOT NULL,
	Type		STRING(1000) NOT NULL,
	Workflow	STRING(1000) NOT NULL,
	-- Status		STRING(128) NOT NULL,
	Error		STRING(1000),
	Created		TIMESTAMP NOT NULL,
	Started		TIMESTAMP,
	Finished	TIMESTAMP,
	CodeRevision	STRING(1000),

	-- LastEvent	TIMESTAMP,
	-- NumEvents	INT64 NOT NULL,

	CONSTRAINT TypeEnum CHECK (Type IN ('patching')),
	CONSTRAINT FK_JobWorkflow FOREIGN KEY (Workflow) REFERENCES Workflows (Name),	
) PRIMARY KEY (ID);

CREATE TABLE PatchingJobs (
	ID		STRING(36) NOT NULL,
	ReproOpts	BYTES NOT NULL,
	ReproSyz	INT64 NOT NULL,
	ReproC		INT64,
	KernelConfig	INT64 NOT NULL,
	SyzkallerCommit	STRING(100) NOT NULL,

	CONSTRAINT FK_PatchingJobJob FOREIGN KEY (ID) REFERENCES Jobs (ID),	
) PRIMARY KEY (ID);

CREATE TABLE TrajectorySpans (
	JobID		STRING(36) NOT NULL,
	Type 		STRING(1000) NOT NULL,
	Nesting 	INT64 NOT NULL,
	Seq		INT64 NOT NULL,
	Name		STRING(1000) NOT NULL,
	Timestamp	TIMESTAMP NOT NULL,
	Finished	BOOL NOT NULL,
	Duration	INT64,
	Error		STRING(1000),
	NestedError	BOOL,
	Args		JSON,
	Results		JSON,
	Instruction	STRING(MAX),
	Prompt		STRING(MAX),
	Reply		STRING(MAX),
	Thoughts	STRING(MAX),

	CONSTRAINT TypeEnum CHECK (Type IN ('flow', 'action', 'agent', 'llm', 'tool')),
	CONSTRAINT FK_EventJob FOREIGN KEY (JobID) REFERENCES Jobs (ID),	
) PRIMARY KEY (JobID, Seq);

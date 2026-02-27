CREATE TABLE SessionTestSteps (
    ID STRING(36) NOT NULL, -- UUID
    SessionID STRING(36) NOT NULL,
    TestName STRING(256) NOT NULL,
    Title STRING(256) NOT NULL,
    LogURI STRING(1024),
    FindingID STRING(36),
    Target STRING(36) NOT NULL,
    Result STRING(36) NOT NULL,
    CreatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
    CONSTRAINT FK_SessionTestStepsSessionID FOREIGN KEY (SessionID) REFERENCES Sessions (ID),
    CONSTRAINT FK_SessionTestStepsTest FOREIGN KEY (SessionID, TestName) REFERENCES SessionTests (SessionID, TestName),
    CONSTRAINT FK_SessionTestStepsFindingID FOREIGN KEY (FindingID) REFERENCES Findings (ID),
    CONSTRAINT SessionTestStepTargetEnum CHECK (Target IN ('patched', 'base')),
    CONSTRAINT SessionTestStepResultEnum CHECK (Result IN ('passed', 'failed', 'error')),
) PRIMARY KEY (ID);

CREATE INDEX SessionTestStepsBySession ON SessionTestSteps(SessionID);
CREATE UNIQUE INDEX NoDupSessionTestSteps ON SessionTestSteps(SessionID, TestName, Title, Target);

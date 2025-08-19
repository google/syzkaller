ALTER TABLE SessionTests DROP CONSTRAINT ResultEnum;
ALTER TABLE SessionTests ADD CONSTRAINT ResultEnum CHECK (Result IN ('passed', 'failed', 'error', 'running', 'skipped'));
CREATE INDEX SessionTestsByResult ON SessionTests(SessionID, Result);

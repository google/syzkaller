ALTER TABLE SessionTests DROP CONSTRAINT ResultEnum;
ALTER TABLE SessionTests ADD CONSTRAINT ResultEnum CHECK (Result IN ('passed', 'failed', 'error', 'running'));
DROP INDEX SessionTestsByResult;

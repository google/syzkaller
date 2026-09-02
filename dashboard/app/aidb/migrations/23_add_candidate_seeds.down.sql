ALTER TABLE TrajectorySpans DROP COLUMN Artifacts;
DROP TABLE ClientSeedCursors;
DROP INDEX CandidateSeedsByTarget;
ALTER TABLE CandidateSeeds DROP CONSTRAINT FK_CandidateSeedJob;
DROP TABLE CandidateSeeds;

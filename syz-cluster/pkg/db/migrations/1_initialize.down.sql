-- Delete constraints first as these may create ciruclar dependencies.
ALTER TABLE Patches DROP CONSTRAINT FK_SeriesPatches;
ALTER TABLE Builds DROP CONSTRAINT FK_Series;
ALTER TABLE Sessions DROP CONSTRAINT FK_SeriesSessions;
ALTER TABLE Series DROP CONSTRAINT FK_SeriesLatestSession;
ALTER TABLE SessionTests DROP CONSTRAINT FK_SessionResults;
ALTER TABLE SessionTests DROP CONSTRAINT FK_BaseBuild;
ALTER TABLE SessionTests DROP CONSTRAINT FK_PatchedBuild;
ALTER TABLE Findings DROP CONSTRAINT FK_SessionCrashes;
ALTER TABLE Findings DROP CONSTRAINT FK_TestCrashes;
ALTER TABLE SessionReports DROP CONSTRAINT FK_SessionReports;
ALTER TABLE ReportReplies DROP CONSTRAINT FK_ReplyReportID;

-- Spanner does not let drop tables without first deleting the indices.
DROP INDEX SeriesByPublishedAt;
DROP INDEX SeriesByExtID;
DROP INDEX PatchesBySeriesAndSeq;
DROP INDEX LastSuccessfulBuild;
DROP INDEX SessionsByFinishedAt;
DROP INDEX NoDupFindings;
DROP INDEX NoDupSessionReports;
DROP INDEX SessionReportsByStatus;
DROP INDEX SessionReportsByMessageID;

DROP TABLE ReportReplies;
DROP TABLE Findings;
DROP TABLE SessionTests;
DROP TABLE SessionReports;
DROP TABLE Patches;
DROP TABLE Builds;
DROP TABLE Sessions;
DROP TABLE Series;

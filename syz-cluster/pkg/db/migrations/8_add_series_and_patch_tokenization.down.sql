-- Revert search by patch and series names
DROP INDEX SeriesIndex;
ALTER TABLE Series DROP COLUMN TitleSubstringTokens;
DROP INDEX PatchesIndex;
ALTER TABLE Patches DROP COLUMN TitleSubstringTokens;
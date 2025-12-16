-- Revert search by patch and series names
DROP INDEX SeriesIndex;
ALTER TABLE Series DROP COLUMN TitleTokens;
DROP INDEX PatchesIndex;
ALTER TABLE Patches DROP COLUMN TitleTokens;

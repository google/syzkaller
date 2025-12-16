-- Enable search by patch and series names
ALTER TABLE Series ADD COLUMN TitleTokens TOKENLIST AS (TOKENIZE_FULLTEXT(Title)) HIDDEN;
CREATE SEARCH INDEX SeriesIndex ON Series(TitleTokens);
ALTER TABLE Patches ADD COLUMN TitleTokens TOKENLIST AS (TOKENIZE_FULLTEXT(Title)) HIDDEN;
CREATE SEARCH INDEX PatchesIndex ON Patches(TitleTokens);

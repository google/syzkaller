-- Enable search by patch and series names
ALTER TABLE Series ADD COLUMN TitleSubstringTokens TOKENLIST AS (TOKENIZE_SUBSTRING(Title, relative_search_types=>["phrase"])) HIDDEN;
CREATE SEARCH INDEX SeriesIndex ON Series(TitleSubstringTokens);
ALTER TABLE Patches ADD COLUMN TitleSubstringTokens TOKENLIST AS (TOKENIZE_SUBSTRING(Title, relative_search_types=>["phrase"])) HIDDEN;
CREATE SEARCH INDEX PatchesIndex ON Patches(TitleSubstringTokens);

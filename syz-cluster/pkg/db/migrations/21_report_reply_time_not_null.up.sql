-- The column is always set by the code and has no meaningful NULL state.
--
-- SessionReports.Moderation and SessionReports.Reporter are in the same
-- situation, but Spanner does not allow changing NOT NULL constraints on
-- index key columns, and dropping/recreating NoDupSessionReports would
-- temporarily lift the uniqueness guarantee that the code relies on.
-- They are left nullable in the schema.
ALTER TABLE ReportReplies ALTER COLUMN Time TIMESTAMP NOT NULL;

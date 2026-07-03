ALTER TABLE Sessions ADD COLUMN ReportLevel STRING(256);
ALTER TABLE Sessions ADD CONSTRAINT check_report_level CHECK (ReportLevel IN ('all', 'bugs', 'none'));

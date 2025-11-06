CREATE TABLE BaseFindings (
    CommitHash STRING(64) NOT NULL,
    Config STRING(256) NOT NULL,
    Arch STRING(64) NOT NULL,
    Title STRING(512) NOT NULL,
) PRIMARY KEY (CommitHash, Config, Arch, Title);

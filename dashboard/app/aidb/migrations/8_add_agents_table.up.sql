DROP TABLE Workflows;

CREATE TABLE Agents (
    AgentName     STRING(100) NOT NULL,
    LastActive    TIMESTAMP NOT NULL,
) PRIMARY KEY(AgentName);

CREATE TABLE Workflows (
    AgentName     STRING(100) NOT NULL,
    Name          STRING(1000) NOT NULL,
    Type          STRING(1000) NOT NULL,
) PRIMARY KEY (AgentName, Name),
INTERLEAVE IN PARENT Agents ON DELETE CASCADE;

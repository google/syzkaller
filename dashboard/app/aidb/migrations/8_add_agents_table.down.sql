DROP TABLE Workflows;
DROP TABLE Agents;

CREATE TABLE Workflows (
    Name          STRING(1000) NOT NULL,
    Type          STRING(1000) NOT NULL,
    LastActive    TIMESTAMP NOT NULL,
) PRIMARY KEY (Name);

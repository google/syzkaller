CREATE TABLE JobComments (
    ID          STRING(36) NOT NULL,
    ReportingID STRING(36) NOT NULL,
    ExtID       STRING(1000) NOT NULL,
    Author      STRING(1000) NOT NULL,
    BodyURI     STRING(MAX) NOT NULL,
    Date        TIMESTAMP NOT NULL,
    CONSTRAINT FK_JobComments_Reporting FOREIGN KEY (ReportingID) REFERENCES JobReporting (ID),
) PRIMARY KEY (ID);

CREATE UNIQUE INDEX JobCommentsByExtID ON JobComments(ExtID);
CREATE INDEX JobCommentsByReportingID ON JobComments(ReportingID);

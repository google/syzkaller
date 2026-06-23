-- Optimizes LoadNamespaceJobs for the /ns/ai page.
CREATE INDEX JobsNamespaceCreated ON Jobs(Namespace, Created DESC);

-- Optimizes LoadBugJobs.
CREATE INDEX JobsBugIDCreated ON Jobs(BugID, Created DESC);

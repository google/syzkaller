-- Optimizes LoadBugIDsWithPendingPatch.
CREATE INDEX JobsPendingFixes ON Jobs(Namespace, Type, Correct);

-- Optimizes StartJob (the agent queue).
CREATE INDEX JobsQueue ON Jobs(Namespace, Started);

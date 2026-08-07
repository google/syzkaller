-- Optimizes LoadFinishedReproCJobs.
CREATE INDEX JobsFinishedReproC ON Jobs(Workflow, Created DESC) STORING (Finished, BugID, Results, Error, Args);

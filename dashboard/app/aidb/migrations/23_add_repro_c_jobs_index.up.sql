-- Optimizes LoadFinishedReproCJobs.
CREATE INDEX JobsFinishedReproC ON Jobs(Workflow, Finished, Created DESC);

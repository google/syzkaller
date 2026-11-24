-- Optimizes CountUnfinishedJobs.
CREATE INDEX JobsUnfinished ON Jobs(Namespace, Finished, Type);

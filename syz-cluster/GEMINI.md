# Syz-Cluster

It's a distributed patch series fuzzing/testing infrasture that:
* Polls mailing list archives for new patch series.
* Builds / Fuzzes / Collects the findings.
* Reports the findings as emails under each corresponding patch series.

Look into README.md for more details.

The system is deployed on a GKE cluster and uses Argo Workflows for orchestration of individual series processing.

## Overall implementation approach
* Actual interaction with the DB should happen inside `pkg/db` repositories.
* Higher level logic is in `pkg/service`.
* The end components should have the minimal amount of logic, prefer to create/reuse testable `pkg/` packages if more logic is needed.
* Components communicate with each other via API that is defined in `pkg/api`.
* Spanner is used as a database. Changes are done as migrations, which are defined in `pkg/db/migrations`.
* Each component has its own:
  * Dockerfile
  * Makefile target
  * K8S or Argo workflow template to deploy it.

## Testing approach
* Each DB repository should have low level tests, for which we use a Spanner emulator. Each test runs with its own temporary DB with already all migrations applied.
  * Whenever you need a repository object for tests, don't mock it directly, but instead just create one and fill it with test data.
* When writing tests, always verify if there exist helper methods in the package that may let you write them more concisely.
* `controller` API tests are in `pkg/controller/api_test.go`.
* Don't try to build the docker containers and don't try to deploy them to K8S.
* ALWAYS run all Go tests in `syz-cluster`, they are fast:
  `CI=true ./tools/syz-env go test ./syz-cluster/...`

## Notes for individual components
* `dashboard` is mean to be read-only web interface, it should not accept any API commands.
* Most of the API (except for reporting API) is served by the `controller` component.

## Database Schema & Migrations
* Spanner emulator enforces FK constraints strictly. Ensure you create parent entities first in tests.
* To drop a table in a migration, you MUST drop its indices first.
* Spanner rejects timestamps in the future. In tests, use `time.Now()` or sequential past timestamps. Avoid `time.Now().Add(...)`.

## API Design
* API endpoints should generally be idempotent. Use `Upsert` or `Replace` semantics where appropriate to handle retries.
* Validate all required fields, especially Foreign Keys. Missing FK fields (e.g. empty `FindingID`) will cause 500 errors from the DB layer if not caught early.

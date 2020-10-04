# Maintainer's Guide

## Linear history

We preserve linear history and have merge commits disabled in repository settings.
Pull requests (PR) have only 2 options:
- **Rebase and merge**\
  This is preferred if all commits in the PR are properly squashed/fixed already,
  as it preserves commits in the PR (takes all commits in the PR as is and adds them
  on top of the master HEAD).
- **Squash and merge**\
  This is preferred if the PR contains fix ups as separate commits and/or other clutter
  in commit organization (squashes all commits in the PR into one commit and adds it
  on top of the master HEAD, also allows to edit commit subject/description).

## PR checks (CI)

`cla/google` check needs to pass before merging.

CI testing generally needs to pass before merging.\
Exceptions may be infrastrcture flakes (especially in external services: `codecov`, `ci/fuzzit`);
one-off timeouts/OOMs (but not if this PR itself makes them much more frequent).
All static checking warnings and testing errors are considered hard errors.

## Tests

Adding tests for new code and bug fixes is generally encouraged. Ask contributors to add tests.

However, some code is easier to test, while some is harder. Some examples of cases where
it's easier to add tests (should be added): abstract functionalities without external dependencies
(e.g. parsers, data transformations, calculations); code with established testing infrastrcture
(adding new tests is just adding one more of the same). Examples of cases where it's harder
to add tests (may be not added, but still welcome if one wants to go above and beyond):
code with external dependancies that are not easy to fake out (qemu, kernel, image, etc);
code without established testing infrastrcture where adding one test would require building
the whole infrastrcture first.

## Use your judgement

There are no strict rules for reviews/ownership at the moment. Use your judgement.

If you are maintaining a particular area of the project (e.g. support for one OS),
it is OK to merge your own changes without further review (especially smaller and
if CI gives green light). It's also OK to review and merge changes to other parts
of the project. But loop in other maintainers if you don't feel confident or need
additional feedback/review.

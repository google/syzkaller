# Covermerger, how it works
## Coverage signal lifetime
Syzkaller relies on KCOV to get information about the actual basic blocks executed
by kernel code.
This tool consumes `line:col` pairs that are coming from `addr2line(pc)` where `pc`
is the actual `pc` where we observed KCOV instrumentation hit.

## What do the dashboard numbers mean
Understanding the coverage percentages displayed on the dashboard can be tricky.
These numbers represent neither pure basic block coverage nor pure line coverage.

Instead, the dashboard shows the percentage of lines with coverage signals where at least one basic block
attributed to that line was executed.

Here's why this matters:

A single line of code can contain multiple basic blocks.

Covermerger reports a "hit" for a line even if only one out of several basic blocks on that line was covered.
For example, if a line has two basic blocks and only one is covered, we report a hit (50% basic block coverage
for that line, but 100% line coverage in our dashboard's context).

Essentially, dashboard coverage will always be greater than or equal to basic block coverage.

## How this tool works
Covermerger's primary function is to merge coverage signals from various kernel versions and configurations.
It provides daily, monthly, and quarterly aggregations.

### Merging Process
Independent File Processing: Each file is processed on its own.

Same Version: If coverage signals come from the exact same version of a file, their hit counts are simply added together.

Different Versions: When merging signals from different file versions (e.g., if a file changed multiple times within
a month), a diff-tool is used to identify equivalent lines across versions.

Projection to Latest Version: All merged signals are projected onto the latest available kernel version within the
aggregation period. For the current month, the target file version may change with each merge run. For past months,
the latest commit available at the end of that month is used as the target version.

Consider a scenario where a file changed three times in a month, and not all lines were included in every build.
Covermerger intelligently combines the signals to provide a comprehensive view despite these variations.

## Update frequency
Merge jobs are automated via [cron.yaml](/dashboard/app/cron.yaml) and follow this schedule:
1. Daily Aggregations: Updated every day. Batch jobs typically refresh "today" and "yesterday" numbers.
2. Monthly Aggregations: Updated weekly, with the current month's data refreshed 4-5 times per month.
3. Quarterly Aggregations: Also updated weekly.

We retain original coverage signals for at least one year, allowing for regeneration of data if needed.

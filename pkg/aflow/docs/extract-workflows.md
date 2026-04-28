# Aflow Data Extraction Tool

## Overview

The Aflow Data Extraction Tool is designed to export agentic workflow execution data from the syzbot dashboard for offline analysis and optimization. It leverages a JSON API exposed by the dashboard to fetch workflow runs and stores them in a structured directory format.

## Design

### Dashboard Integration

To enable data extraction, the syzbot dashboard supports a `json=1` query parameter on AI job pages:

1.  **AI Jobs List**: `/{ns}/ai?json=1` returns a JSON list of all AI jobs in the namespace, including metadata like workflow type, status, and code revision.
2.  **AI Job Details**: `/ai_job?id=<id>&json=1` returns detailed information about a specific job, including the full execution trajectory (spans representing flow, action, agent, and tool executions).

These endpoints use the existing `writeJSONVersionOf` helper to serialize the internal page data structures to JSON.

### Extraction Script

The extraction process is automated by a bash script located at `tools/extract_workflows.sh`.

#### Usage

```bash
./tools/extract_workflows.sh <dashboard_url> <commit> [output_dir]
```

-   `dashboard_url`: The URL of the AI jobs page (e.g., `http://localhost:8080/linux/ai`).
-   `commit`: A syzkaller commit hash. The script will only extract workflows run on this commit or newer (based on date comparison).
-   `output_dir`: Optional directory to store the extracted data. Defaults to `extracted_workflows`.

#### Process

1.  **Commit Date**: The script gets the timestamp of the specified commit using `git log`.
2.  **Fetch List**: It calls the dashboard list endpoint with `?json=1` to get all jobs.
3.  **Filter**: It iterates over the jobs and filters out those older than the specified commit date, unless the job's `CodeRevision` matches the target commit exactly.
4.  **Fetch Details**: For each matching job, it calls the job details endpoint with `?json=1` to get the full trajectory.
5.  **Store**: It creates a directory named after the workflow type (e.g., `repro`, `repro-c`) inside the output directory and saves the job details as a JSON file named `<job_id>.json`.

## Output Structure

The extracted data is organized as follows:

```
output_dir/
├── repro/
│   ├── 12345678-1234-5678-1234-567812345678.json
│   └── ...
├── repro-c/
│   ├── ...
└── ...
```

Each JSON file contains a snapshot of a workflow run, suitable for analysis by other tools.

# Prepare coverage aggregation pipeline

Assuming you have the coverage `*.jsonl` files in some bucket:
1. Create BigQuery table.
2. Start data transfers from the bucket to BigQuery table.

Coverage merger job is consuming data from BQ table and store aggregations
in the Spanner DB.

The dots in BQ table name are not supported, thus:
1. For the namespace "upstream" the expected BQ table name is "upstream".
2. For the namespace "android-6.12" the expected BQ table name is "android-6-12".


### Create new BigQuery table for coverage data
```bash
bq mk \
  --table \
  --description "android 6.12" \
  --time_partitioning_field timestamp \
  --time_partitioning_type DAY \
  --require_partition_filter=true \
  --clustering_fields file_path,kernel_commit,hit_count \
  syzkaller:syzbot_coverage.android-6-12 \
  ./pkg/coveragedb/bq-schema.json
```

### Add new data transfer
```bash
bq mk \
  --transfer_config \
  --display_name=ci-android-6-12-bucket-to-syzbot_coverage \
  --params='{"destination_table_name_template":"android-6-12",
  "data_path_template": "gs://$COVERAGE_STREAM_BUCKET/ci-android-6.12/*.jsonl",
  "allow_jagged_rows": false,
  "allow_quoted_newlines": false,
  "delete_source_files": true,
  "encoding": "UTF8",
  "field_delimiter": ",",
  "file_format": "JSON",
  "ignore_unknown_values": false,
  "max_bad_records": "0",
  "parquet_enable_list_inference": false,
  "parquet_enum_as_string": false,
  "preserve_ascii_control_characters": false,
  "skip_leading_rows": "0",
  "use_avro_logical_types": false,
  "write_disposition": "APPEND"
  }' \
  --project_id=syzkaller \
  --data_source=google_cloud_storage \
  --target_dataset=syzbot_coverage
```

### List BigQuery data transfers
```bash
bq ls \
  --transfer_config \
  --transfer_location=us-central1 \
  --project_id=syzkaller
```
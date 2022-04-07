# Prometheus metrics

syz-manager metrics are exposed at the URI `/metrics` on the http endpoint.
Currently exported prometheus metrics from the manager are `syz_exec_total`, `syz_corpus_cover` and `syz_crash_total`.

These metrics can be ingested using following prometheus client configuration:
```
scrape_configs:
- job_name: syzkaller
  scrape_interval: 10s
  static_configs:
  - targets:
    - localhost:56741
```

Values are reset to zero at syz-manager restart and only reflect for current execution of syz-manager.

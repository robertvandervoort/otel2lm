# otel2lm

Brings an existing OpenTelemetry Collector setup into LogicMonitor without touching the backend it already feeds (Grafana LGTM, Jaeger, Elastic). 

Single file, Python 3.8+, needs PyYAML (`python3 -m pip install pyyaml`).

## Steps

```bash
python3 otel2lm.py inventory otel-collector.yaml                 # what's there, and what will confuse LM
python3 otel2lm.py discover --prometheus http://host:9090        # service.name values -> mapping.yaml skeleton
python3 otel2lm.py render otel-collector.yaml mapping.yaml -o otel-collector.lm.yaml
python3 otel2lm.py lmotel-fix lmotel/config.yaml -o lmotel/config.fixed.yaml
python3 otel2lm.py resources mapping.yaml [--apply]              # resources must exist before spans mean anything
python3 otel2lm.py dashboard mapping.yaml [--apply]              # "OTel - Services (APM)"
python3 otel2lm.py verify mapping.yaml                           # traces and logs landing per resource
python3 otel2lm.py wizard                                        # the same, interactively
```

- `render` and `lmotel-fix` never overwrite their input; diff the output, then validate it with the collector itself:
`docker run --rm -v $PWD/otel-collector.lm.yaml:/c.yaml otel/opentelemetry-collector-contrib validate --config=/c.yaml`
- `resources` and `dashboard` are dry runs unless `--apply` is given. They use LMv1 credentials from `LOGICMONITOR_ACCOUNT`, `LOGICMONITOR_ACCESS_ID`, `LOGICMONITOR_ACCESS_KEY` (pass them with `docker run --env-file`, never on the command line).

## What `render` does

| Adds | Why |
| --- | --- |
| `traces/lm`, `metrics/lm`, `logs/lm` pipelines | LogicMonitor gets its own copy with LM identity; the existing pipelines keep their processors and exporters |
| `transform/lm_entity` | maps `service.name` to a resource name (mapping file), sets `host.name`, `system.hostname`, `resource.type=host`, keeps the container id as `container.id`, fills `deployment.environment.name` |
| `transform/lm_logs` | same mapping for logs (also by the docker `container` label), sets `system.hostname`, deletes `system.collectorid`, copies trace and span ids into attributes for the Logs trace id column |
| `spanmetrics/lm` | RED metrics with bounded dimensions only (no session ids, error text or referrers, each of which becomes an LM instance per value) |
| `otlp/logicmonitor`, `logicmonitor` exporters | traces and metrics via the LM OTel collector; logs straight to the LM Logs API (lmotel only forwards file logs) |

It also removes LogicMonitor exporters that were bolted onto the shared pipelines, since those send LM raw SemConv with no entity mapping.

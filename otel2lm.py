#!/usr/bin/env python3
"""otel2lm: bring an existing OpenTelemetry Collector setup into LogicMonitor without touching
the backend it already feeds (Grafana LGTM, Jaeger, Elastic, ...).

It does what was done by hand on nas, as repeatable steps:

  inventory   CONFIG                     what the collector receives, exports and pipes today
  discover    --prometheus URL           service.name values seen in spanmetrics -> mapping skeleton
  render      CONFIG MAPPING -o OUT      add LogicMonitor-only pipelines with the entity transforms
  lmotel-fix  CONFIG -o OUT              stop HTTP 413s in the LM OTel collector (virtual fs, NICs, batching)
  resources   MAPPING [--apply]          create the LM resources and group the telemetry will land on
  dashboard   MAPPING [--apply]          an SRE "Services (APM)" dashboard over those resources
  verify      MAPPING                    does each resource have traces (APM) and logs (Log Usage)?
  wizard                                 interactive walk-through of all of the above

Inputs never get overwritten; every change is written to a new file to diff and review.
LM API calls use LMv1 from LOGICMONITOR_ACCOUNT / LOGICMONITOR_ACCESS_ID / LOGICMONITOR_ACCESS_KEY
and default to a dry run. Needs Python 3.8+ and PyYAML.

Why the transforms look the way they do (verified on a live portal, 2026-10-14):
  traces   LM ties a span to the resource whose name equals resource attr host.name (resource.type=host);
           it never creates the resource, so `resources` must run first.
  metrics  pushed OTLP metrics attach to the resource named by host.name, and only materialise when
           they match an LM datasource (LogicMonitor_APM_*).
  logs     the logicmonitor exporter matches resource attributes against resource properties;
           system.hostname matches, host.name and system.displayname do not, and a leftover
           system.collectorid wins first, so it is deleted.
"""
import argparse, base64, copy, hashlib, hmac, json, os, re, sys, time, urllib.error, urllib.parse, urllib.request

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("otel2lm needs PyYAML:  python3 -m pip install pyyaml")

LM_TRACES, LM_METRICS, LM_LOGS = "traces/lm", "metrics/lm", "logs/lm"
LM_OTLP_EXPORTER, LM_LOGS_EXPORTER = "otlp/logicmonitor", "logicmonitor"
SPANMETRICS_LM = "spanmetrics/lm"
# Bounded dimensions only: every distinct value becomes an LM instance.
SPANMETRICS_DIMENSIONS = ["http.request.method", "http.response.status_code", "rum.route", "rum.country", "rum.section", "rum.cta", "rum.vital.name", "rum.vital.rating"]
UNBOUNDED_HINTS = ("session", "error.message", "referrer", "user", "url.full", "query", "id")


# ------------------------------------------------------------------ yaml io
class _Dumper(yaml.SafeDumper):
    pass


def _str_presenter(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"' if any(c in data for c in ':#{}[]"\'') or data.strip() != data else None)


_Dumper.add_representer(str, _str_presenter)
_Dumper.ignore_aliases = lambda self, data: True


def load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def dump(obj, path, header=""):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        if header:
            f.write("".join(f"# {l}\n" for l in header.splitlines()))
        yaml.dump(obj, f, Dumper=_Dumper, sort_keys=False, width=200, default_flow_style=False)


def load_mapping(path):
    m = load(path)
    for key in ("fallback_resource", "resources"):
        if key not in m:
            sys.exit(f"mapping {path}: missing '{key}' (see mapping.example.yaml)")
    for r in m["resources"]:
        r.setdefault("services", [f"^{re.escape(r['name'])}$"])
        r.setdefault("containers", [r["name"]])
        r.setdefault("properties", {})
    return m


# ------------------------------------------------------------------ inventory
def pipelines(cfg):
    return ((cfg.get("service") or {}).get("pipelines") or {})


def inventory(cfg):
    out = []
    pl = pipelines(cfg)
    out.append(f"receivers:  {', '.join(cfg.get('receivers') or {}) or '-'}")
    out.append(f"processors: {', '.join(cfg.get('processors') or {}) or '-'}")
    out.append(f"connectors: {', '.join(cfg.get('connectors') or {}) or '-'}")
    out.append(f"exporters:  {', '.join(cfg.get('exporters') or {}) or '-'}")
    out.append("pipelines:")
    for name, p in pl.items():
        out.append(f"  {name:14} {','.join(p.get('receivers', [])):28} -> [{','.join(p.get('processors', []))}] -> {','.join(p.get('exporters', []))}")
    lm_exp = [e for e in (cfg.get("exporters") or {}) if "logicmonitor" in e]
    lm_pl = [p for p in pl if p in (LM_TRACES, LM_METRICS, LM_LOGS)]
    out.append("")
    out.append(f"LogicMonitor exporters: {', '.join(lm_exp) or 'none'}")
    out.append(f"LogicMonitor-only pipelines: {', '.join(lm_pl) or 'none'}")
    for name, p in pl.items():
        if name in (LM_TRACES, LM_METRICS, LM_LOGS):
            continue
        shared = [e for e in p.get("exporters", []) if "logicmonitor" in e]
        if shared:
            out.append(f"  ! pipeline {name} sends to {', '.join(shared)} with the other backend's processors; "
                       "LM then sees raw SemConv with no entity mapping. `render` moves LM to its own pipeline.")
    for cname, c in (cfg.get("connectors") or {}).items():
        if cname.startswith("spanmetrics"):
            dims = [d.get("name", "") for d in c.get("dimensions") or []]
            bad = [d for d in dims if any(h in d for h in UNBOUNDED_HINTS)]
            if bad:
                out.append(f"  ! connector {cname} has unbounded dimensions {bad}: fine for Prometheus, one LM instance per value")
    return "\n".join(out)


# ------------------------------------------------------------------ discover
def discover(prom_url, metric="traces_span_metrics_calls_total"):
    q = urllib.parse.urlencode({"query": f"count by (service_name, service_namespace) ({metric})"})
    with urllib.request.urlopen(f"{prom_url.rstrip('/')}/api/v1/query?{q}", timeout=20) as r:
        res = json.load(r)["data"]["result"]
    seen = sorted({(x["metric"].get("service_name", ""), x["metric"].get("service_namespace", "")) for x in res})
    resources = []
    for svc, ns in seen:
        if not svc:
            continue
        base = re.sub(r"-(rum|browser|web-rum)$", "", svc)
        hit = next((r for r in resources if r["name"] == base), None)
        if hit:
            hit["services"].append(f"^{re.escape(svc)}$")
        else:
            resources.append({"name": base, "services": [f"^{re.escape(svc)}$"], "containers": [base], "properties": {"service.namespace": ns or "default"}})
    return {"portal": os.environ.get("LOGICMONITOR_ACCOUNT", "yourportal"), "collector_id": 0, "fallback_resource": "otel-host",
            "group": "OTel resources", "lm_otel_endpoint": "host.docker.internal:14317", "resources": resources}


# ------------------------------------------------------------------ render
def ottl_str(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def entity_statements(m):
    st = ['set(attributes["container.id"], attributes["host.name"]) where attributes["container.id"] == nil and attributes["host.name"] != nil and IsMatch(attributes["host.name"], "^[0-9a-f]{12}$")']
    for r in m["resources"]:
        rx = "|".join(f"(?:{p})" for p in r["services"])
        st.append(f'set(attributes["lm.entity"], {ottl_str(r["name"])}) where attributes["lm.entity"] == nil and IsMatch(attributes["service.name"], {ottl_str(rx)})')
    st += [
        f'set(attributes["lm.entity"], {ottl_str(m["fallback_resource"])}) where attributes["lm.entity"] == nil',
        'set(attributes["host.name"], attributes["lm.entity"])',
        'set(attributes["system.hostname"], attributes["lm.entity"])',
        'set(attributes["system.displayname"], attributes["lm.entity"])',
        'set(attributes["resource.type"], "host")',
        'set(attributes["deployment.environment.name"], attributes["deployment.environment"]) where attributes["deployment.environment.name"] == nil and attributes["deployment.environment"] != nil',
        'delete_key(attributes, "lm.entity")',
    ]
    return st


def log_statements(m):
    containers = [c for r in m["resources"] for c in r["containers"]]
    by_container = {c: r["name"] for r in m["resources"] for c in r["containers"]}
    log_ctx = [f'set(resource.attributes["lm.entity"], {ottl_str(by_container[c])}) where attributes["container"] == {ottl_str(c)}' for c in containers]
    res_ctx = []
    for r in m["resources"]:
        rx = "|".join(f"(?:{p})" for p in r["services"])
        res_ctx.append(f'set(attributes["lm.entity"], {ottl_str(r["name"])}) where attributes["lm.entity"] == nil and IsMatch(attributes["service.name"], {ottl_str(rx)})')
    res_ctx += [
        f'set(attributes["lm.entity"], {ottl_str(m["fallback_resource"])}) where attributes["lm.entity"] == nil',
        'set(attributes["system.hostname"], attributes["lm.entity"])',
        'set(attributes["host.name"], attributes["lm.entity"])',
        'delete_key(attributes, "lm.entity")',
        'delete_key(attributes, "system.collectorid")',
    ]
    trace_ids = [
        'set(attributes["trace_id"], trace_id.string) where trace_id.string != "00000000000000000000000000000000"',
        'set(attributes["span_id"], span_id.string) where span_id.string != "0000000000000000"',
    ]
    return [{"context": "log", "statements": trace_ids + log_ctx}, {"context": "resource", "statements": res_ctx}]


def render(cfg, m):
    """Return a new config with LM-only pipelines; existing pipelines keep their processors and exporters."""
    cfg = copy.deepcopy(cfg)
    notes = []
    procs = cfg.setdefault("processors", {})
    conns = cfg.setdefault("connectors", {})
    exps = cfg.setdefault("exporters", {})
    pl = cfg.setdefault("service", {}).setdefault("pipelines", {})

    stm = entity_statements(m)
    procs["transform/lm_entity"] = {"error_mode": "ignore",
                                    "trace_statements": [{"context": "resource", "statements": stm}],
                                    "metric_statements": [{"context": "resource", "statements": list(stm)}]}
    procs["transform/lm_logs"] = {"error_mode": "ignore", "log_statements": log_statements(m)}
    procs.setdefault("batch", {})
    procs["batch/lm"] = {"send_batch_size": 300, "send_batch_max_size": 300, "timeout": "5s"}
    conns[SPANMETRICS_LM] = {"namespace": "traces.span.metrics", "histogram": {"explicit": {"buckets": ["10ms", "50ms", "100ms", "250ms", "500ms", "1s", "2.5s", "5s", "10s", "30s"]}},
                             "dimensions": [{"name": d} for d in SPANMETRICS_DIMENSIONS], "dimensions_cache_size": 2000,
                             "aggregation_temporality": "AGGREGATION_TEMPORALITY_CUMULATIVE", "metrics_flush_interval": "60s"}
    exps[LM_OTLP_EXPORTER] = {"endpoint": m.get("lm_otel_endpoint", "host.docker.internal:14317"), "tls": {"insecure": True}}
    exps[LM_LOGS_EXPORTER] = {"endpoint": f"https://{m.get('portal', 'yourportal')}.logicmonitor.com/rest",
                              "api_token": {"access_id": "${env:LOGICMONITOR_ACCESS_ID}", "access_key": "${env:LOGICMONITOR_ACCESS_KEY}"},
                              "logs": {"resource_mapping_op": "or"}}

    # Anything that already sent to LogicMonitor from a shared pipeline now goes through the LM pipelines instead.
    for name, p in pl.items():
        lm = [e for e in p.get("exporters", []) if "logicmonitor" in e]
        if lm:
            p["exporters"] = [e for e in p["exporters"] if e not in lm]
            notes.append(f"removed {lm} from pipeline {name}; LogicMonitor now gets that signal from its own pipeline")
        if not p["exporters"]:
            notes.append(f"pipeline {name} has no exporters left; delete it or add the original backend back")

    recv = list(cfg.get("receivers") or {})
    otlp = [r for r in recv if r.split("/")[0] == "otlp"] or ["otlp"]
    log_recv = otlp + [r for r in recv if r.split("/")[0] in ("loki", "filelog", "syslog", "fluentforward")]
    traces_src = next((n for n in pl if n.split("/")[0] == "traces" and n != LM_TRACES), None)
    if traces_src:
        if SPANMETRICS_LM not in pl[traces_src].setdefault("exporters", []):
            pl[traces_src]["exporters"].append(SPANMETRICS_LM)
        notes.append(f"{SPANMETRICS_LM} fed from pipeline {traces_src} (raw spans, before LM identity, like spanmetrics for Grafana)")
    else:
        notes.append(f"no traces pipeline found: {SPANMETRICS_LM} is defined but fed by nothing")
    pl[LM_TRACES] = {"receivers": otlp, "processors": ["transform/lm_entity", "batch"], "exporters": [LM_OTLP_EXPORTER]}
    pl[LM_METRICS] = {"receivers": otlp + ([SPANMETRICS_LM] if traces_src else []), "processors": ["transform/lm_entity", "batch/lm"], "exporters": [LM_OTLP_EXPORTER]}
    pl[LM_LOGS] = {"receivers": log_recv, "processors": ["transform/lm_logs", "batch"], "exporters": [LM_LOGS_EXPORTER]}
    notes.append(f"added {LM_TRACES}, {LM_METRICS}, {LM_LOGS}; other pipelines keep their processors")
    notes.append("the logicmonitor exporter needs LOGICMONITOR_ACCESS_ID/KEY in the collector's environment (an API-only user is enough for logs)")
    return cfg, notes


# ------------------------------------------------------------------ lmotel 413 fix
def lmotel_fix(cfg):
    cfg = copy.deepcopy(cfg)
    notes = []
    for rname, r in (cfg.get("receivers") or {}).items():
        if rname.split("/")[0] != "hostmetrics":
            continue
        sc = r.setdefault("scrapers", {})
        if "filesystem" in sc:
            sc["filesystem"] = sc["filesystem"] or {}
            sc["filesystem"]["include_virtual_filesystems"] = False
            sc["filesystem"].setdefault("exclude_fs_types", {"fs_types": ["overlay", "squashfs", "tmpfs", "nsfs", "proc", "sysfs", "cgroup2"], "match_type": "strict"})
            notes.append(f"{rname}: filesystem scraper skips virtual and overlay filesystems")
        if "network" in sc:
            sc["network"] = sc["network"] or {}
            sc["network"]["exclude"] = {"interfaces": ["^(veth|br-|docker|cali|flannel|cni).*"], "match_type": "regexp"}
            notes.append(f"{rname}: network scraper skips container and bridge interfaces")
    procs = cfg.setdefault("processors", {})
    procs["batch/metrics"] = {"send_batch_size": 300, "send_batch_max_size": 300, "timeout": "5s"}
    for name, p in pipelines(cfg).items():
        if name.split("/")[0] == "metrics":
            p["processors"] = [x for x in p.get("processors", []) if x.split("/")[0] != "batch"] + ["batch/metrics"]
            notes.append(f"pipeline {name}: batch/metrics (300 points per request) replaces any other batch processor")
    if not notes:
        notes.append("no hostmetrics receiver or metrics pipeline found; nothing to change")
    return cfg, notes


# ------------------------------------------------------------------ LM REST
class LM:
    def __init__(self, account=None):
        self.account = account or os.environ.get("LOGICMONITOR_ACCOUNT", "")
        self.aid = os.environ.get("LOGICMONITOR_ACCESS_ID", "")
        self.key = os.environ.get("LOGICMONITOR_ACCESS_KEY", "")
        if not (self.account and self.key):
            sys.exit("set LOGICMONITOR_ACCOUNT, LOGICMONITOR_ACCESS_ID and LOGICMONITOR_ACCESS_KEY (or a bearer token in ..._KEY)")

    def call(self, method, path, query="", body=None):
        data = json.dumps(body) if body is not None else ""
        req = urllib.request.Request(f"https://{self.account}.logicmonitor.com/santaba/rest{path}" + (f"?{query}" if query else ""),
                                     data=data.encode() if data else None, method=method)
        if self.aid:
            epoch = str(int(time.time() * 1000))
            sig = base64.b64encode(hmac.new(self.key.encode(), (method + epoch + data + path).encode(), hashlib.sha256).hexdigest().encode()).decode()
            req.add_header("Authorization", f"LMv1 {self.aid}:{sig}:{epoch}")
        else:
            req.add_header("Authorization", f"Bearer {self.key}")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Version", "3")
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except ValueError:
                return e.code, {}

    def find(self, path, flt, fields="id,name"):
        st, j = self.call("GET", path, "size=50&fields=" + fields + "&filter=" + urllib.parse.quote(flt))
        return (j.get("items") or []) if st == 200 else []


def resources(m, apply=False):
    lm = LM(m.get("portal"))
    group, coll = m.get("group", "OTel resources"), m.get("collector_id")
    out = []
    g = lm.find("/device/groups", f'name:"{group}",parentId:1')
    gid = g[0]["id"] if g else None
    if not gid:
        out.append(f"group {group}: missing" + (" -> creating" if apply else " (would create)"))
        if apply:
            st, j = lm.call("POST", "/device/groups", body={"name": group, "parentId": 1, "description": "Resources that OpenTelemetry telemetry maps onto (otel2lm)"})
            gid = j.get("id"); out.append(f"  {st} {gid or j.get('errorMessage')}")
    names = [m["fallback_resource"]] + [r["name"] for r in m["resources"]]
    for r in [{"name": m["fallback_resource"], "properties": {}}] + m["resources"]:
        have = lm.find("/device/devices", f'name:"{r["name"]}"') or lm.find("/device/devices", f'displayName:"{r["name"]}"', "id,name,displayName")
        if have:
            out.append(f"exists   {r['name']} (id {have[0]['id']})"); continue
        props = {"resource.type": "host", "deployment.environment": "production", **{k: str(v) for k, v in r.get("properties", {}).items()}}
        body = {"name": r["name"], "displayName": r["name"], "description": "created by otel2lm", "hostGroupIds": str(gid or 1),
                "customProperties": [{"name": k, "value": v} for k, v in props.items()]}
        if coll:
            body["preferredCollectorId"] = int(coll)
        if not apply:
            out.append(f"missing  {r['name']} (would create with {', '.join(f'{k}={v}' for k, v in props.items())})"); continue
        st, j = lm.call("POST", "/device/devices", body=body)
        out.append(f"create   {r['name']}: {st} {j.get('id') or j.get('errorMessage')}")
    if not coll:
        out.append("note: collector_id is 0, so LM picks a collector; set it to the collector that can reach these hosts")
    out.append(f"{len(names)} resources checked" + ("" if apply else "; dry run, pass --apply to create"))
    return "\n".join(out)


def dashboard(m, apply=False):
    """One SRE dashboard over the mapped resources: RED from traces plus log volume."""
    lm = LM(m.get("portal"))
    group = m.get("group", "OTel resources")
    def full(ds):
        it = lm.find("/setting/datasources", f'name:"{ds}"', "id,name,displayName")
        if not it:
            return None
        d = it[0]
        return d["name"] if d["displayName"] == d["name"] else f'{d["displayName"]} ({d["name"]})'
    def dp(name, ds, datapoint, agg="SUM", kind="line"):
        return {"name": name, "dataPointName": datapoint, "dataSourceFullName": full(ds), "deviceGroupFullPath": {"value": group, "isGlob": False},
                "deviceDisplayName": {"value": "*", "isGlob": True}, "instanceName": {"value": "*", "isGlob": True}, "consolidateFunction": "average",
                "aggregateFunction": agg, "display": {"option": "custom", "legend": "##RESOURCENAME## ##INSTANCE##", "type": kind, "color": "Auto"}}
    def cg(name, points, unit):
        return {"type": "cgraph", "name": name, "colSpan": 2, "rowSpan": 1, "graphInfo": {"title": name, "verticalLabel": unit, "aggregate": False, "minValue": 0, "maxValue": "NaN",
                "dataPoints": points, "virtualDataPoints": [], "globalConsolidateFunction": "VaST"}}
    svc = "LogicMonitor_APM_Services"
    if not full(svc):
        return f"{svc} does not exist yet: send traces first (LM creates it on the first mapped span)"
    widgets = [
        {"type": "alert", "name": "Active alerts", "colSpan": 2, "rowSpan": 1, "filters": {"group": group + "*", "host": "*", "dataSource": "*", "instance": "*", "dataPoint": "*", "severity": "warn,error,critical", "acked": "all", "sdted": "all", "cleared": "no"}},
        cg("Requests per minute by service", [dp("ops", svc, "OperationCount")], "ops/min"),
        cg("Errors per minute by service", [dp("err", svc, "ErrorOperationCount", kind="area")], "errors/min"),
        cg("Average duration by service", [dp("ms", svc, "Duration", agg="AVERAGE")], "ms"),
    ]
    if full("LogUsage"):
        widgets.append(cg("Log events per minute", [dict(dp("logs", "LogUsage", "event_received", kind="area"), display={"option": "custom", "legend": "##RESOURCENAME##", "type": "area", "color": "Auto"})], "events/min"))
    name = m.get("dashboard_name", "OTel - Services (APM)")   # its own name: --apply replaces a dashboard of the same name
    if not apply:
        return f"would (re)build dashboard '{name}' with {len(widgets)} widgets over group '{group}'; pass --apply"
    out = []
    for d in lm.find("/dashboard/dashboards", f'name:"{name}"'):
        lm.call("DELETE", f"/dashboard/dashboards/{d['id']}")
    st, j = lm.call("POST", "/dashboard/dashboards", body={"name": name, "groupId": 1, "description": "otel2lm: RED per service from OpenTelemetry traces", "sharable": True})
    if st != 200:
        return f"dashboard: {st} {j.get('errorMessage')}"
    out.append(f"dashboard {name} -> {j['id']}")
    for w in widgets:
        st, r = lm.call("POST", "/dashboard/widgets", body=dict(w, dashboardId=j["id"]))
        out.append(f"  {st} {w['name']}" + ("" if st == 200 else f" !! {(r.get('errorMessage') or '')[:160]}"))
    return "\n".join(out)


def verify(m):
    lm = LM(m.get("portal"))
    rows = [("resource", "exists", "traces (APM)", "logs (Log Usage)")]
    for name in [m["fallback_resource"]] + [r["name"] for r in m["resources"]]:
        dev = lm.find("/device/devices", f'name:"{name}"') or lm.find("/device/devices", f'displayName:"{name}"', "id,name,displayName")
        if not dev:
            rows.append((name, "no", "-", "-")); continue
        st, j = lm.call("GET", f"/device/devices/{dev[0]['id']}/devicedatasources", "size=500&fields=id,dataSourceName")
        ds = {d["dataSourceName"] for d in j.get("items") or []}
        rows.append((name, "yes", "yes" if any(d.startswith("LogicMonitor_APM_Services") for d in ds) else "no",
                     "yes" if any("LogUsage" in d.replace(" ", "") for d in ds) else "no"))
    w = [max(len(r[i]) for r in rows) for i in range(4)]
    lines = ["  ".join(c.ljust(w[i]) for i, c in enumerate(r)) for r in rows]
    lines.insert(1, "  ".join("-" * x for x in w))
    misses = [r[0] for r in rows[1:] if "no" in r[1:]]
    if misses:
        lines.append("")
        lines.append("no traces: check host.name on the spans equals the resource name and that lmotel forwards them.")
        lines.append("no logs: check system.hostname on the log resource and that system.collectorid is gone.")
    return "\n".join(lines)


# ------------------------------------------------------------------ wizard
def ask(prompt, default=""):
    v = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return v or default


def wizard():
    print(__doc__.split("\n\n")[0])
    print()
    steps = ["inventory a collector config", "discover services from Prometheus spanmetrics", "render LM pipelines into a new config",
             "fix lmotel HTTP 413s", "check or create LM resources", "build the SRE dashboard", "verify traces and logs land", "quit"]
    state = {"config": "", "mapping": "mapping.yaml"}
    while True:
        print()
        for i, s in enumerate(steps, 1):
            print(f"  {i}. {s}")
        c = ask("step", "1")
        try:
            if c == "1":
                state["config"] = ask("collector config", state["config"] or "otel-collector.yaml")
                print(inventory(load(state["config"])))
            elif c == "2":
                url = ask("Prometheus URL", "http://localhost:9090")
                m = discover(url)
                dump(m, state["mapping"], "otel2lm mapping: edit names, regexes, containers and properties, then render")
                print(f"wrote {state['mapping']} with {len(m['resources'])} resources; review it before rendering")
            elif c == "3":
                state["config"] = ask("collector config", state["config"] or "otel-collector.yaml")
                state["mapping"] = ask("mapping", state["mapping"])
                out = ask("output", re.sub(r"(\.ya?ml)$", r".lm\1", state["config"]))
                cfg, notes = render(load(state["config"]), load_mapping(state["mapping"]))
                dump(cfg, out, f"generated by otel2lm render from {os.path.basename(state['config'])}")
                print("\n".join(" - " + n for n in notes) + f"\nwrote {out}; diff it against {state['config']}")
            elif c == "4":
                src = ask("lmotel config", "config.yaml")
                out = ask("output", re.sub(r"(\.ya?ml)$", r".fixed\1", src))
                cfg, notes = lmotel_fix(load(src))
                dump(cfg, out, f"generated by otel2lm lmotel-fix from {os.path.basename(src)}")
                print("\n".join(" - " + n for n in notes) + f"\nwrote {out}")
            elif c in ("5", "6"):
                m = load_mapping(ask("mapping", state["mapping"]))
                fn = resources if c == "5" else dashboard
                print(fn(m, False))
                if ask("apply these changes in LogicMonitor? (yes/no)", "no").lower() == "yes":
                    print(fn(m, True))
            elif c == "7":
                print(verify(load_mapping(ask("mapping", state["mapping"]))))
            elif c in ("8", "q", "quit"):
                return
        except (OSError, KeyError, ValueError, urllib.error.URLError) as e:
            print(f"!! {e}")


# ------------------------------------------------------------------ cli
def main(argv=None):
    ap = argparse.ArgumentParser(prog="otel2lm", description="Bring an existing OpenTelemetry Collector setup into LogicMonitor.")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("inventory"); p.add_argument("config")
    p = sub.add_parser("discover"); p.add_argument("--prometheus", required=True); p.add_argument("-o", "--out", default="mapping.yaml")
    p = sub.add_parser("render"); p.add_argument("config"); p.add_argument("mapping"); p.add_argument("-o", "--out", required=True)
    p = sub.add_parser("lmotel-fix"); p.add_argument("config"); p.add_argument("-o", "--out", required=True)
    for name in ("resources", "dashboard"):
        p = sub.add_parser(name); p.add_argument("mapping"); p.add_argument("--apply", action="store_true")
    p = sub.add_parser("verify"); p.add_argument("mapping")
    sub.add_parser("wizard")
    a = ap.parse_args(argv)
    if a.cmd == "inventory":
        print(inventory(load(a.config)))
    elif a.cmd == "discover":
        m = discover(a.prometheus)
        dump(m, a.out, "otel2lm mapping: edit names, regexes, containers and properties, then render")
        print(f"wrote {a.out} with {len(m['resources'])} resources")
    elif a.cmd == "render":
        if os.path.abspath(a.out) == os.path.abspath(a.config):
            sys.exit("refusing to overwrite the input; write to a new file and diff it")
        cfg, notes = render(load(a.config), load_mapping(a.mapping))
        dump(cfg, a.out, f"generated by otel2lm render from {os.path.basename(a.config)}")
        print("\n".join(" - " + n for n in notes)); print(f"wrote {a.out}")
    elif a.cmd == "lmotel-fix":
        if os.path.abspath(a.out) == os.path.abspath(a.config):
            sys.exit("refusing to overwrite the input; write to a new file and diff it")
        cfg, notes = lmotel_fix(load(a.config))
        dump(cfg, a.out, f"generated by otel2lm lmotel-fix from {os.path.basename(a.config)}")
        print("\n".join(" - " + n for n in notes)); print(f"wrote {a.out}")
    elif a.cmd == "resources":
        print(resources(load_mapping(a.mapping), a.apply))
    elif a.cmd == "dashboard":
        print(dashboard(load_mapping(a.mapping), a.apply))
    elif a.cmd == "verify":
        print(verify(load_mapping(a.mapping)))
    else:
        wizard()


if __name__ == "__main__":
    main()

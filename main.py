import os, yaml, argparse, time, orjson
from concurrent.futures import ThreadPoolExecutor

RULES_DIR = "rules"
MAX_WORKERS = os.cpu_count()

def compile_rule(path):
    r = yaml.safe_load(open(path, 'r'))
    checks = []
    for key, cond in r["detection"].items():
        if key == "condition":
            continue
        for field, val in cond.items():
            op   = field.split("|")[1] if "|" in field else "equals"
            attr = field.split("|")[0].lower()
            vals = [v.lower() for v in (val if isinstance(val, list) else [val])]
            if op == "contains":
                chk = lambda logv, vs=vals: any(v in logv for v in vs)
            elif op == "endswith":
                chk = lambda logv, vs=vals: any(logv.endswith(v) for v in vs)
            else:                                   # equals
                chk = lambda logv, vs=vals: logv in vs
            checks.append((attr, chk))
    return {"meta": {
                "title": r.get("title"), "id": r.get("id"),
                "desc": r.get("description", ""), "level": r.get("level","")},
            "checks": checks }

rules = [compile_rule(os.path.join(RULES_DIR, f))
         for f in os.listdir(RULES_DIR) if f.endswith(".yaml")]
print(f"▶ Loaded {len(rules)} rules.")


def match_log(log):
    low = {k.lower(): str(v).lower() for k, v in log.items()}
    return [r["meta"] for r in rules
            if all(chk(low.get(f, "")) for f, chk in r["checks"])]

def detect_format(path):
    first = open(path,'rb').read(2).strip()
    return "jsonl" if first.startswith(b"{") and b"\n" in open(path,'rb').read(200) else "json"

def stream(path, is_jsonl, workers=MAX_WORKERS):
    if not is_jsonl:                             
        blob = orjson.loads(open(path,'rb').read())
        logs = blob if isinstance(blob, list) else [blob]
        for lg in logs:
            yield lg, match_log(lg)
    else:                                       
        with ThreadPoolExecutor(max_workers=workers) as pool:
            for lg, hits in pool.map(parse_line, open(path,'rb'), chunksize=256):
                if lg: yield lg, hits

def parse_line(line):
    try:
        lg = orjson.loads(line)
        return lg, match_log(lg)
    except orjson.JSONDecodeError:
        return None, None

def show(lg, hits):
    if not hits: return
    hdr = lg.get("Image") or lg.get("CommandLine") or "<log>"
    print(f"\n📝 {hdr}")
    for h in hits:
        print(f"  ✅ {h['title']} (id: {h['id']}  level: {h['level']})")
        if h['desc']: print(f"     ↳ {h['desc']}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("file", help="log.json  yoki  logs.json")
    ap.add_argument("--workers", type=int, default=MAX_WORKERS)
    args = ap.parse_args()

    fmt = detect_format(args.file)
    t0  = time.perf_counter()
    total = hits = 0

    for lg, matched in stream(args.file, fmt=="json", args.workers):
        total += 1
        if matched:
            hits += 1
            show(lg, matched)

    print(f"\n⏱ {total} log, {hits} hit  —  {time.perf_counter()-t0:.2f}s   ({fmt})")

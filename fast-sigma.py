
import base64, ipaddress, re, sys, time, os
from pathlib import Path
from typing import Dict

import orjson, yaml, dill as pickle

RULES_DIR   = Path("rules")
CACHE_FILE  = Path(".sigma_cache.pkl")
DEFAULT_FLD = "commandline"


OPS = {
    "contains":   lambda v, ls: any(x in v for x in ls),
    "endswith":   lambda v, ls: any(v.endswith(x) for x in ls),
    "equals":     lambda v, ls: v in ls,
    "startswith": lambda v, ls: any(v.startswith(x) for x in ls),
    "re":         lambda v, ls: any(re.search(x, v, re.I) for x in ls),
    "cidr":       lambda v, ls: any(ipaddress.ip_address(v) in ipaddress.ip_network(n, strict=False)
                                    for n in ls if _is_ip(v)),
    "base64offset": lambda v, ls, off=5: any(x in _b64dec(v, off) for x in ls),
}

def _is_ip(s):
    try: ipaddress.ip_address(s); return True
    except ValueError: return False

def _b64dec(s, off):
    try: return base64.b64decode(s[off:] + '===').decode(errors="ignore").lower()
    except Exception: return ""


def _compile_rule(path: Path):
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    checks = []
    def add(field, val, op_override=None):
        op   = op_override or (field.split("|")[1] if "|" in field else "equals")
        if op not in OPS: raise ValueError(op)
        attr = field.split("|")[0].lower()
        lst  = [str(v).lower() for v in (val if isinstance(val, list) else [val])]
        fn   = lambda s, f=OPS[op], ls=lst: f(s, ls)
        checks.append((attr, fn))

    for key, cond in raw.get("detection", {}).items():
        if key == "condition": continue
        if isinstance(cond, dict):
            for f, v in cond.items(): add(f, v)
        elif isinstance(cond, list):
            for item in cond:
                if isinstance(item, dict):
                    for f, v in item.items(): add(f, v)
                else:
                    add(DEFAULT_FLD, item, "contains")
    return {
        "meta": {
            "title": raw.get("title"),
            "id":    raw.get("id"),
            "level": raw.get("level", ""),
            "desc":  raw.get("description", "")
        },
        "checks": checks or [("noop", lambda *_: False)]
    }

def _compile_all(dir_: Path):
    rules = []
    for fname in os.listdir(dir_):
        if fname.lower().endswith((".yml", ".yaml")):
            rule = None
            try:   rule = _compile_rule(dir_ / fname)
            except Exception as e: print(f"⚠️ Skip {fname}: {e}")
            if rule: rules.append(rule)
    return rules

def _load_rules():
    if CACHE_FILE.exists():
        try:
            return pickle.load(CACHE_FILE.open("rb"))
        except Exception:
            print("⚠️  Kesh buzilgan, qayta kompilyatsiya…")
    rules = _compile_all(RULES_DIR)
    pickle.dump(rules, CACHE_FILE.open("wb"))
    return rules

class Matcher:
    def __init__(self, rules): self.rules = rules
    def match(self, log: Dict):
        low = {k.lower(): str(v).lower() for k, v in log.items()}
        return [r["meta"] for r in self.rules
                if all(fn(low.get(f, "")) for f, fn in r["checks"])]

def _show(log, hits):
    if not hits: return
    head = log.get("Image") or log.get("CommandLine") or "<log>"
    print(f"\n📝 {head}")
    for h in hits:
        lvl = f" [{h['level']}]" if h["level"] else ""
        print(f"  ✅ {h['title']}{lvl} (id: {h['id']})")
        if h["desc"]: print("     ↳", h["desc"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Foydalanish: python main.py log.json")
        sys.exit(1)

    log_path = Path(sys.argv[1])
    data = orjson.loads(log_path.read_bytes())
    logs = data if isinstance(data, list) else [data]

    RULES = _load_rules()
    matcher = Matcher(RULES)
    print(f"⚡ {len(RULES)} qoida tayyor")

    t0 = time.perf_counter()
    tot = hit = 0
    for lg in logs:
        res = matcher.match(lg); _show(lg, res)
        tot += 1; hit += bool(res)
    print(f"\n⏱ {tot} log, {hit} hit — {time.perf_counter()-t0:.3f}s")
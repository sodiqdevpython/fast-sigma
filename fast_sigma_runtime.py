from fast_sigma import _load_rules, Matcher

RULES = _load_rules()
MATCHER = Matcher(RULES)

def analyze_log(log: dict):
    low = {k.lower(): str(v).lower() for k, v in log.items()}
    return [r["meta"] for r in MATCHER.rules if all(fn(low.get(f, "")) for f, fn in r["checks"])]

from time import perf_counter_ns
from fast_sigma_runtime import analyze_log

log = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell -nop -w hidden -EncodedCommand something -ExecutionPolicy Bypass",
    "ParentImage": "C:\\Windows\\explorer.exe"
}

start = perf_counter_ns()
for _ in range(100):
    result = analyze_log(log)

for match in result:
    print(f"✅ {match['title']}  ({match['id']})")

end = perf_counter_ns()
print(f"{(end - start) / 1e6:.3f} ms")
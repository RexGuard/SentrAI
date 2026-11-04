import json, time, statistics as st, urllib.request, sys
from concurrent.futures import ThreadPoolExecutor
import os
H={"Authorization":"Bearer "+os.environ.get("TOKEN","t")}
B=os.environ.get("CORE","http://127.0.0.1:8100")
paths=["/ui/overview","/ui/audit?limit=60","/ui/incidents?closed=false","/ui/approvals","/ui/machines","/risk"]
def get(p):
    t=time.perf_counter()
    try:
        r=urllib.request.urlopen(urllib.request.Request(B+p,headers=H));n=len(r.read());c=r.status
    except urllib.error.HTTPError as e: n=0;c=e.code
    return (time.perf_counter()-t)*1000,n,c
def pct(a,q): a=sorted(a);return a[min(len(a)-1,int(len(a)*q))]
print(f"{'endpoint':32}{'code':>5}{'KB':>8}{'p50 ms':>9}{'p95 ms':>9}{'max':>8} | 20 at once: p50 ms  p95 ms  req/s")
for p in paths:
    get(p);s=[get(p) for _ in range(10)]
    t=[x[0] for x in s]
    t0=time.perf_counter()
    with ThreadPoolExecutor(20) as ex: par=list(ex.map(get,[p]*40))
    wall=time.perf_counter()-t0;pt=[x[0] for x in par]
    print(f"{p:32}{s[0][2]:>5}{s[0][1]/1024:>8.1f}{st.median(t):>9.1f}{pct(t,.95):>9.1f}{max(t):>8.1f} | {st.median(pt):>12.0f}{pct(pt,.95):>8.0f}{len(pt)/wall:>8.0f}")

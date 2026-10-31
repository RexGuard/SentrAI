"""Fills a throwaway core with fake web, ssh and db events across 20 machines. Usage: python seed.py [batches of 100]"""
import json, os, sys, random, urllib.request, time
H={"Authorization":"Bearer "+os.environ.get("TOKEN","t"),"Content-Type":"application/json"}
BASE=os.environ.get("CORE","http://127.0.0.1:8100")
def post(p,b):
    r=urllib.request.Request(BASE+p,json.dumps(b).encode(),H);return json.load(urllib.request.urlopen(r))
raws=["GET /index.php?id=1' OR '1'='1 HTTP/1.1 200","GET /../../etc/passwd HTTP/1.1 404","POST /wp-login.php HTTP/1.1 401","GET /admin HTTP/1.1 403",
"Failed password for root from 10.0.0.9 port 22 ssh2","GET /health HTTP/1.1 200","GET /static/app.js HTTP/1.1 200","sqlmap/1.7 GET /?id=1 UNION SELECT 1,2"]
random.seed(1);t0=time.time();n=0
for batch in range(int(sys.argv[1]) if len(sys.argv)>1 else 40):
    evs=[{"host":f"srv-{random.randint(1,20):02d}","layer":random.choice(["web","ssh","db"]),"source":"nginx","src_ip":f"203.0.113.{random.randint(1,250)}","raw":random.choice(raws)} for _ in range(100)]
    post("/events",evs);n+=100
print(n,"events in",round(time.time()-t0,1),"s")

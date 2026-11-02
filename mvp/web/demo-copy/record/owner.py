import requests, hmac, hashlib, base64, struct, time, json, sys
s=requests.Session(); B="http://127.0.0.1:8000"
r=s.post(B+"/auth/register-owner",json={"code":sys.argv[1],"name":"Demo Owner","email":"owner@example.com","password":"DemoPass!2026long"}); print(r.status_code,r.text)
r=s.post(B+"/auth/authenticator/start",headers={"X-SentrAI-Web":"1"}); print(r.status_code); sec=r.json()["secret"]
def totp(sec):
    k=base64.b32decode(sec+"="*(-len(sec)%8)); c=struct.pack(">Q",int(time.time()//30)); h=hmac.new(k,c,hashlib.sha1).digest(); o=h[-1]&15
    return "%06d"%((struct.unpack(">I",h[o:o+4])[0]&0x7fffffff)%1000000)
r=s.post(B+"/auth/authenticator/confirm",json={"code":totp(sec)},headers={"X-SentrAI-Web":"1"}); print(r.status_code)
json.dump({"secret":sec,"cookies":s.cookies.get_dict()},open("acct.json","w"))
print(s.get(B+"/auth/me").text)

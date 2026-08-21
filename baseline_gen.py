import json, time, os
from collections import defaultdict, Counter

EVE="/var/log/suricata/eve.json"
OUT="/var/log/suricata/ml_baseline.json"
TARGET_SAMPLES=300
INTERVAL=10

def classify(sig):
    s=sig.lower()
    if "brute force" in s:return "SSH_BRUTEFORCE"
    if "ssh connection" in s:return "SSH_ATTEMPT"
    if "xmas" in s:return "NMAP_XMAS"
    if "null scan" in s:return "NMAP_NULL"
    if "fin scan" in s:return "NMAP_FIN"
    if "syn scan" in s:return "NMAP_SYN"
    if "icmp flood" in s:return "ICMP_FLOOD"
    if "syn flood" in s:return "TCP_SYN_FLOOD"
    if "lateral" in s and "dmz" in s:return "LATERAL_DMZ"
    if "lateral" in s and "hr" in s:return "LATERAL_HR"
    if "icmp ping" in s:return "ICMP_PING"
    return "OTHER"

def parse(pos):
    alerts=[]
    try:
        if os.path.getsize(EVE) < pos: pos=0
        with open(EVE) as f:
            f.seek(pos)
            for line in f:
                try:e=json.loads(line)
                except:continue
                if e.get("event_type")=="alert":
                    alerts.append({"src":e.get("src_ip",""),"dst":e.get("dest_ip",""),
                        "dport":e.get("dest_port",0),"proto":e.get("proto",""),
                        "type":classify(e.get("alert",{}).get("signature",""))})
            pos=f.tell()
    except FileNotFoundError:return [],pos
    return alerts,pos

def vectors(alerts):
    st=defaultdict(lambda:{"n":0,"dsts":set(),"ports":set(),"protos":set(),"types":set(),
        "scan":0,"ssh":0,"flood":0,"lat":0,"vlans":set()})
    for a in alerts:
        s=st[a["src"]];s["n"]+=1;s["dsts"].add(a["dst"]);s["ports"].add(a["dport"])
        s["protos"].add(a["proto"]);s["types"].add(a["type"])
        t=a["type"]
        if "NMAP" in t:s["scan"]+=1
        if "SSH" in t:s["ssh"]+=1
        if "FLOOD" in t:s["flood"]+=1
        if "LATERAL" in t:s["lat"]+=1
        if a["dst"].startswith("192.168.10."):s["vlans"].add(10)
        if a["dst"].startswith("192.168.20."):s["vlans"].add(20)
        if a["dst"].startswith("192.168.30."):s["vlans"].add(30)
    out=[]
    for ip,s in st.items():
        if s["n"]==0:continue
        out.append([s["n"],len(s["dsts"]),len(s["ports"]),len(s["protos"]),len(s["types"]),
            s["scan"],s["ssh"],s["flood"],s["lat"],len(s["vlans"])])
    return out

samples=[]
if os.path.exists(OUT):
    try: samples=json.load(open(OUT))
    except: samples=[]
pos=os.path.getsize(EVE) if os.path.exists(EVE) else 0
print(f"[baseline] collecting NORMAL vectors (have {len(samples)}, target {TARGET_SAMPLES}).")
try:
    while len(samples) < TARGET_SAMPLES:
        time.sleep(INTERVAL)
        alerts,pos=parse(pos)
        v=vectors(alerts)
        samples.extend(v)
        print(f"[baseline] +{len(v)} this cycle -> total {len(samples)}")
except KeyboardInterrupt:
    print("\n[baseline] stopped by user.")
json.dump(samples,open(OUT,"w"),indent=2)
print(f"[baseline] wrote {len(samples)} samples to {OUT}")


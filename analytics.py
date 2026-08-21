import json, time, os, threading, queue
from collections import defaultdict, deque, Counter
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from netmiko import ConnectHandler

EVE="/var/log/suricata/eve.json"
OUT="/var/log/suricata/ml_results.json"
REP="/var/log/suricata/reputation.json"
HIST="/var/log/suricata/history.json"
BASELINE_FILE="/var/log/suricata/ml_baseline.json"
INTERVAL=10
TTL_SECONDS=30

ML_SUSPICIOUS=None
ML_HIGH=None
ML_EXTREME=None
ML_FLAG_AT=None
K_SUSPICIOUS=2.0
K_HIGH=3.0
K_EXTREME=4.0

REP_DECAY_HOURS=24
REP_DECAY_FACTOR=0.8
REP_ESCALATE=5

ENFORCE_MODE="vacl"

PERMIT_SEQ=65000
VACL_MAP="AUTO-QUAR"
VACL_ACL="QUAR-HOSTS"
VACL_VLANS="10,20,30"

_SSH_EXTRA={"conn_timeout":15,"banner_timeout":20,"auth_timeout":20,
"fast_cli":False,"global_delay_factor":2}
CORE_SW={"device_type":"cisco_ios","host":"192.168.99.1","username":"admin",
"password":"cisco123","secret":"cisco123","ssh_config_file":"~/.ssh/config",**_SSH_EXTRA}
PERIM_FW={"device_type":"cisco_ios","host":"10.0.1.1","username":"admin",
"password":"cisco123","secret":"cisco123","ssh_config_file":"~/.ssh/config",**_SSH_EXTRA}

ALLOWLIST_HOSTS={
"192.168.99.1","192.168.99.10","192.168.99.11","192.168.99.12",
"192.168.10.1","192.168.20.1","192.168.30.1",
"192.168.30.10","192.168.30.20","192.168.20.10",
"10.0.1.1","10.0.1.2","127.0.0.1"
}
ALLOWLIST_FLOWS={("192.168.30.10",80),("192.168.30.10",443),("192.168.30.20",53)}
DMZ="192.168.30.0"

active_blocks={}
seq_counter=[10]
rate_win=defaultdict(lambda:deque(maxlen=1000))

enforce_q=queue.Queue()
_state_lock=threading.Lock()
_vacl_active=set()

def _load(p,d):
    if os.path.exists(p):
        try:return json.load(open(p))
        except:return d
    return d

def _save(p,o):
    try:
        tmp=p+".tmp"
        with open(tmp,"w") as f: json.dump(o,f,indent=2)
        os.replace(tmp,p)
    except Exception as e:
        print(f" [WARN] could not write {p}: {e}")

def calibrate_bands(scores):
    global ML_SUSPICIOUS,ML_HIGH,ML_EXTREME,ML_FLAG_AT
    mu=float(np.mean(scores)); sigma=float(np.std(scores)) or 1e-6
    if ML_SUSPICIOUS is None: ML_SUSPICIOUS=round(mu-K_SUSPICIOUS*sigma,4)
    if ML_HIGH is None: ML_HIGH =round(mu-K_HIGH*sigma,4)
    if ML_EXTREME is None: ML_EXTREME =round(mu-K_EXTREME*sigma,4)
    if ML_FLAG_AT is None: ML_FLAG_AT =ML_SUSPICIOUS
    print(f" [ML] baseline scores: mean={mu:.3f} std={sigma:.3f} "
          f"min={float(np.min(scores)):.3f} max={float(np.max(scores)):.3f}")
    print(f" [ML] bands -> SUSPICIOUS<{ML_SUSPICIOUS} HIGH<{ML_HIGH} "
          f"EXTREME<{ML_EXTREME} (flag@{ML_FLAG_AT})")

def load_baseline_model():
    if not os.path.exists(BASELINE_FILE):
        print(" [ML] No baseline - ML disabled.");return None,None
    try:
        data=json.load(open(BASELINE_FILE))
        if len(data)<8:
            print(f" [ML] Baseline too small ({len(data)}).");return None,None
        sc=StandardScaler().fit(data)
        X=sc.transform(data)
        model=IsolationForest(n_estimators=200,contamination=0.05,
                               random_state=42).fit(X)
        calibrate_bands(model.score_samples(X))
        print(f" [ML] Isolation Forest trained on {len(data)} normal samples.")
        return model,sc
    except Exception as e:
        print(f" [ML] load failed: {e}");return None,None

def band_for(score):
    if ML_EXTREME is None: return "NORMAL"
    if score < ML_EXTREME: return "EXTREME"
    if score < ML_HIGH: return "HIGH"
    if score < ML_SUSPICIOUS: return "SUSPICIOUS"
    return "NORMAL"

def iso_score(rows, model, scaler):
    if model is None or scaler is None:
        return {r["ip"]:(False,0.0,"NORMAL") for r in rows}
    feat=[[r["alerts"],r["dsts"],r["ports"],r["protos"],r["types"],
           r["scan"],r["ssh"],r["flood"],r["lat"],r["vlans"]] for r in rows]
    try:
        raw=model.score_samples(scaler.transform(feat))
        out={}
        for i,r in enumerate(rows):
            s=float(raw[i]); out[r["ip"]]=(s<=ML_FLAG_AT, s, band_for(s))
        return out
    except Exception as e:
        print(f" [ML] scoring error: {e}")
        return {r["ip"]:(False,0.0,"NORMAL") for r in rows}

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

ATTACK_NAMES={
"NMAP_XMAS":"Nmap XMAS scan","NMAP_NULL":"Nmap NULL scan","NMAP_FIN":"Nmap FIN scan",
"NMAP_SYN":"Nmap SYN scan","TCP_SYN_FLOOD":"TCP SYN flood","ICMP_FLOOD":"ICMP flood",
"ICMP_PING":"ICMP ping","SSH_BRUTEFORCE":"SSH brute-force","SSH_ATTEMPT":"SSH connection attempt",
"LATERAL_DMZ":"Cross-VLAN lateral -> DMZ","LATERAL_HR":"Cross-VLAN lateral -> HR","OTHER":"Unclassified"}

def parse(pos):
    alerts=[];flows=[]
    try:
        if os.path.getsize(EVE) < pos:
            pos=0
        with open(EVE) as f:
            f.seek(pos)
            for line in f:
                try:e=json.loads(line)
                except:continue
                et=e.get("event_type")
                if et=="alert":
                    dst=e.get("dest_ip","");dport=e.get("dest_port",0)
                    if (dst,dport) in ALLOWLIST_FLOWS:continue
                    alerts.append({"src":e.get("src_ip",""),"dst":dst,"dport":dport,
                        "proto":e.get("proto",""),"sev":e.get("alert",{}).get("severity",3),
                        "type":classify(e.get("alert",{}).get("signature",""))})
                elif et=="flow":
                    flows.append({"src":e.get("src_ip",""),
                        "pkts":e.get("flow",{}).get("pkts_toserver",0)})
            npos=f.tell()
    except FileNotFoundError:return [],[],pos
    return alerts,flows,npos

def features(alerts,flows):
    st=defaultdict(lambda:{"n":0,"dsts":set(),"ports":set(),"protos":set(),"sev":0,
        "sevmin":99,"types":set(),"scan":0,"ssh":0,"icmp":0,"flood":0,"lat":0,"vlans":set(),
        "flows":0,"typecount":Counter()})
    for a in alerts:
        s=st[a["src"]];s["n"]+=1;s["dsts"].add(a["dst"]);s["ports"].add(a["dport"])
        s["protos"].add(a["proto"]);s["sev"]+=a["sev"];s["sevmin"]=min(s["sevmin"],a["sev"])
        s["types"].add(a["type"]);s["typecount"][a["type"]]+=1
        t=a["type"]
        if "NMAP" in t:s["scan"]+=1
        if "SSH" in t:s["ssh"]+=1
        if t=="ICMP_FLOOD":s["flood"]+=1
        if t in("ICMP_PING","ICMP_FLOOD"):s["icmp"]+=1
        if "FLOOD" in t:s["flood"]+=1
        if "LATERAL" in t:s["lat"]+=1
        if a["dst"].startswith("192.168.10."):s["vlans"].add(10)
        if a["dst"].startswith("192.168.20."):s["vlans"].add(20)
        if a["dst"].startswith("192.168.30."):s["vlans"].add(30)
    for fl in flows:st[fl["src"]]["flows"]+=1
    rows=[]
    for ip,s in st.items():
        if s["n"]==0:continue
        rows.append({"ip":ip,"alerts":s["n"],"dsts":len(s["dsts"]),"ports":len(s["ports"]),
            "protos":len(s["protos"]),"sev":s["sev"],"sevmin":s["sevmin"],"types":len(s["types"]),
            "scan":s["scan"],"ssh":s["ssh"],"icmp":s["icmp"],"flood":s["flood"],
            "lat":s["lat"],"vlans":len(s["vlans"]),"flows":s["flows"],
            "typecount":dict(s["typecount"]),"typelist":", ".join(sorted(s["types"]))})
    return rows

def rate_flag(alerts):
    now=time.time();flagged=set()
    for a in alerts:
        dq=rate_win[a["src"]];dq.append(now)
        recent=[t for t in dq if now-t<=3]
        rate_win[a["src"]]=deque(recent,maxlen=1000)
        if len(recent)>=15:flagged.add(a["src"])
    return flagged

def decayed_hits(entry):
    hits=entry.get("hits",0);last=entry.get("last")
    if not last or hits<=0: return hits
    try:
        dt=datetime.fromisoformat(last)
        periods=(datetime.now()-dt).total_seconds()/(REP_DECAY_HOURS*3600)
        if periods>=1: hits=hits*(REP_DECAY_FACTOR**int(periods))
    except:pass
    return hits

def decide(r, ratel, ml_anom, ml_band, rep_hits):
    ip=r["ip"]
    if ip in ALLOWLIST_HOSTS:
        return 0,"allowlisted host","Trusted infrastructure host; excluded from enforcement.",False,100,"ALLOW"
    is_scan=r["scan"]>0
    is_flood=r["flood"]>0
    is_brute=r["ssh"]>0 and ("SSH_BRUTEFORCE" in r["typelist"])
    is_ssh=r["ssh"]>0
    is_lateral=r["lat"]>0
    breadth=r["ports"]+r["dsts"]
    cats=len([t for t in r["typelist"].split(", ")
              if t and t not in ("ICMP_PING","OTHER","SSH_ATTEMPT")])
    any_attack=is_scan or is_flood or is_ssh or is_lateral
    sevmin=r.get("sevmin",99)
    conf=0
    if any_attack: conf+=40
    if ml_anom: conf+=25
    if rep_hits>=REP_ESCALATE: conf+=20
    if breadth>=20: conf+=15
    if sevmin<=1: conf+=20
    elif sevmin<=2: conf+=10
    conf=min(conf,100)
    if not any_attack:
        if sevmin<=1:
            if ml_anom or rep_hits>=REP_ESCALATE:
                return 3,"high-severity unclassified alert (confirmed)",\
                    f"Severity-1 Suricata alert ({r['typelist']}) outside known buckets, corroborated by ML/reputation; quarantined.",bool(ml_anom),max(conf,65),"QUARANTINE"
            return 2,"high-severity unclassified alert",\
                f"Severity-1 Suricata alert ({r['typelist']}) not matching a known attack bucket; watchlisted (previously dropped as benign).",False,max(conf,45),"WATCHLIST"
        if sevmin<=2:
            return 2,"medium-severity unclassified alert",\
                f"Severity-2 Suricata alert ({r['typelist']}) outside known buckets; watchlisted for review.",False,max(conf,30),"WATCHLIST"
        if ml_anom:
            return 2,"ML behavioural anomaly",\
                f"No known attack signature, but behaviour deviates sharply from baseline ({ml_band}); flagged by the Isolation Forest.",True,max(conf,50),"WATCHLIST"
        return 0,"benign traffic","No attack signatures observed; traffic within normal parameters.",False,0,"NONE"
    if cats>=3:
        return 4,f"multi-vector attack ({cats} categories)",\
            f"Host exhibits {cats} distinct attack categories ({r['typelist']}); treated as a coordinated high-severity threat.",False,conf,"FULL BLOCK"
    if rep_hits>=REP_ESCALATE and (is_flood or breadth>=20 or ml_anom):
        return 4,"persistent repeat offender",\
            f"Host has {rep_hits:.1f} decayed reputation hits and is actively attacking; escalated to full block.",False,conf,"FULL BLOCK"
    if is_lateral and is_flood:
        return 4,"cross-VLAN flood","High-rate attack crossing VLAN boundaries; critical.",False,conf,"FULL BLOCK"
    if is_lateral:
        return 3,"cross-VLAN lateral movement",\
            "Attack traffic crosses a VLAN boundary, violating segmentation. Quarantined from the protected segment.",False,conf,"QUARANTINE"
    if is_flood:
        return 2,"active flood / high packet rate","Sustained high-rate traffic consistent with flooding. Watchlisted.",False,conf,"WATCHLIST"
    if is_brute:
        return 2,"SSH brute-force","Repeated SSH auth attempts consistent with credential brute-forcing. Watchlisted.",False,conf,"WATCHLIST"
    if breadth>=20:
        return 2,f"broad scan ({breadth} ports/hosts)",f"Wide reconnaissance across {breadth} ports/hosts. Watchlisted.",False,conf,"WATCHLIST"
    if ml_anom and (is_scan or breadth>=8):
        return 2,"recon escalated by ML anomaly",\
            f"Reconnaissance detected; ML confirms behaviour deviates from baseline ({ml_band}). Escalated to active-attack tier.",True,conf,"WATCHLIST"
    if is_scan or is_ssh:
        return 1,"reconnaissance / probing","Low-volume probing consistent with early-stage reconnaissance. Logged and watched.",False,conf,"WATCH / LOG"
    return 1,"low-level suspicious activity","Minor anomaly logged for observation.",False,conf,"WATCH / LOG"

def cisco_push(dev,cmds,save=False,retries=3):
    last=None
    for _ in range(retries+1):
        try:
            c=ConnectHandler(**dev);c.enable();c.send_config_set(cmds)
            if save:c.save_config()
            c.disconnect();return True
        except Exception as e:
            last=e;time.sleep(2)
    raise last

def ensure_acl_baseline():
    if ENFORCE_MODE=="vacl":
        try:
            c=ConnectHandler(**CORE_SW);c.enable()
            c.send_config_set([
                f"ip access-list extended {VACL_ACL}","exit",
                f"vlan access-map {VACL_MAP} 10",
                f"match ip address {VACL_ACL}","action drop",
                f"vlan access-map {VACL_MAP} 20","action forward"])
            c.disconnect()
            print(f" [INIT] VACL {VACL_MAP} ready on {CORE_SW['host']} (filter bound on first block)")
        except Exception as e:
            print(f" [INIT] VACL baseline failed {CORE_SW['host']}: {e}")
        _ensure_permit(PERIM_FW,"AUTO-BLOCK")
        return
    _ensure_permit(CORE_SW,"VLAN-QUARANTINE")
    _ensure_permit(PERIM_FW,"AUTO-BLOCK")

def _ensure_permit(dev,acl):
    try:
        c=ConnectHandler(**dev);c.enable()
        out=c.send_command(f"show ip access-lists {acl}")
        if "permit ip any any" not in out:
            c.send_config_set([f"ip access-list extended {acl}",
                f"{PERMIT_SEQ} permit ip any any"])
            print(f" [INIT] added safety permit to {acl} on {dev['host']}")
        c.disconnect()
    except Exception as e:
        print(f" [INIT] baseline failed {dev['host']} {acl}: {e}")

def _flush_host_lines(dev,acl,verb):
    removed=0
    c=ConnectHandler(**dev);c.enable()
    out=c.send_command(f"show ip access-lists {acl}")
    for line in out.splitlines():
        p=line.strip().split()
        if len(p)>=2 and p[0].isdigit() and p[1]==verb and "host" in p:
            c.send_config_set([f"ip access-list extended {acl}",f"no {p[0]}"]);removed+=1
    c.disconnect()
    return removed

def reconcile_on_startup():
    if ENFORCE_MODE=="vacl":
        try:
            c=ConnectHandler(**CORE_SW);c.enable()
            c.send_config_set([f"no vlan filter {VACL_MAP} vlan-list {VACL_VLANS}"])
            c.disconnect()
            n=_flush_host_lines(CORE_SW,VACL_ACL,"permit")
            print(f" [INIT] VACL reconciled on {CORE_SW['host']} ({n} removed)")
        except Exception as e:
            print(f" [INIT] VACL reconcile failed {CORE_SW['host']}: {e}")
        try:
            n=_flush_host_lines(PERIM_FW,"AUTO-BLOCK","deny")
            print(f" [INIT] reconciled AUTO-BLOCK on {PERIM_FW['host']} ({n} removed)")
        except Exception as e:
            print(f" [INIT] reconcile failed {PERIM_FW['host']}: {e}")
        _vacl_active.clear()
        return
    for dev,acl in [(CORE_SW,"VLAN-QUARANTINE"),(PERIM_FW,"AUTO-BLOCK")]:
        try:
            n=_flush_host_lines(dev,acl,"deny")
            print(f" [INIT] reconciled {acl} on {dev['host']} ({n} removed)")
        except Exception as e:
            print(f" [INIT] reconcile failed {dev['host']}: {e}")

def _apply_block(ip,scope,seq,target):
    if ENFORCE_MODE=="vacl":
        cisco_push(CORE_SW,[f"ip access-list extended {VACL_ACL}",
            f"{seq} permit ip host {ip} {target}"])
        if not _vacl_active:
            cisco_push(CORE_SW,[f"vlan filter {VACL_MAP} vlan-list {VACL_VLANS}"])
        _vacl_active.add(seq)
        if scope=="FULL-BLOCK":
            cisco_push(PERIM_FW,["ip access-list extended AUTO-BLOCK",
                f"{seq} deny ip host {ip} any"])
        return
    if scope=="QUARANTINE":
        cisco_push(CORE_SW,["ip access-list extended VLAN-QUARANTINE",
            f"{seq} deny ip host {ip} {target}"])
    elif scope=="FULL-BLOCK":
        cisco_push(PERIM_FW,["ip access-list extended AUTO-BLOCK",
            f"{seq} deny ip host {ip} any"])

def _apply_unblock(ip,scope,seq):
    if ENFORCE_MODE=="vacl":
        _vacl_active.discard(seq)
        if not _vacl_active:
            cisco_push(CORE_SW,[f"no vlan filter {VACL_MAP} vlan-list {VACL_VLANS}"])
        cisco_push(CORE_SW,[f"ip access-list extended {VACL_ACL}",f"no {seq}"])
        if scope=="FULL-BLOCK":
            cisco_push(PERIM_FW,["ip access-list extended AUTO-BLOCK",f"no {seq}"])
        return
    if scope=="QUARANTINE":
        cisco_push(CORE_SW,["ip access-list extended VLAN-QUARANTINE",f"no {seq}"])
    elif scope=="FULL-BLOCK":
        cisco_push(PERIM_FW,["ip access-list extended AUTO-BLOCK",f"no {seq}"])

def enforce_worker():
    while True:
        job=enforce_q.get()
        act,ip,scope,seq,target,tries=job
        try:
            if act=="block":
                _apply_block(ip,scope,seq,target);print(f" [ENF] applied {scope} {ip} [{target}] seq{seq}")
            else:
                _apply_unblock(ip,scope,seq);print(f" [TTL] removed {scope} {ip} seq{seq}")
        except Exception as e:
            if tries<5:
                print(f" [ENF] {act} {ip} failed (try {tries+1}), re-queuing: {e}")
                time.sleep(3);enforce_q.put((act,ip,scope,seq,target,tries+1))
            else:
                print(f" [ENF] {act} {ip} GAVE UP after {tries+1} tries: {e}")
        finally:
            enforce_q.task_done()

def enforce(ip,tier,target):
    if ip in ALLOWLIST_HOSTS:return None,None
    if tier==3: scope="QUARANTINE"
    elif tier>=4: scope="FULL-BLOCK"
    else: return None,None
    with _state_lock:
        seq=seq_counter[0];seq_counter[0]+=10
    enforce_q.put(("block",ip,scope,seq,target,0))
    return scope,seq

def unenforce(ip):
    with _state_lock:
        b=active_blocks.pop(ip,None)
    if not b:return
    enforce_q.put(("unblock",ip,b["scope"],b["seq"],b.get("target","any"),0))

def ttl_worker():
    while True:
        now=time.time()
        with _state_lock:
            expired=[k for k,v in active_blocks.items() if v["expires"]<=now]
        for ip in expired:
            unenforce(ip)
        time.sleep(2)

def print_block_state():
    with _state_lock:
        snap=dict(active_blocks)
    if snap:
        now=time.time();print(" [STATE] active blocks:")
        for ip,b in snap.items():
            print(f"      {ip} {b['scope']} (expires {int(b['expires']-now)}s)")
    else:print(" [STATE] no active blocks")

def merge_counter(h,tc):
    c=Counter(h.get("attack_counts",{}));c.update(tc);h["attack_counts"]=dict(c)

def run():
    rep=_load(REP,{});hist=_load(HIST,{})
    pos=os.path.getsize(EVE) if os.path.exists(EVE) else 0
    cyc=1
    threading.Thread(target=ttl_worker,daemon=True).start()
    threading.Thread(target=enforce_worker,daemon=True).start()
    ensure_acl_baseline()
    reconcile_on_startup()
    ml_model,ml_scaler=load_baseline_model()
    print(f"IDS/IPS analytics running (mode={ENFORCE_MODE}; decay+confidence+banded ML"
          f"+blind-spot guard+queued/resilient SSH)")
    while True:
        print(f"\n[{datetime.now():%H:%M:%S}] cycle {cyc}")
        alerts,flows,pos=parse(pos)
        if alerts:
            rows=features(alerts,flows)
            rl=rate_flag(alerts)
            iso=iso_score(rows,ml_model,ml_scaler)
            for r in rows:
                e=rep.setdefault(r["ip"],{"first":datetime.now().isoformat(),"hits":0,"maxtier":0})
                rep_h=decayed_hits(e)
                anom,score,band=iso.get(r["ip"],(False,0.0,"NORMAL"))
                tier,reason,expl,ml_used,conf,action=decide(r,r["ip"] in rl,anom,band,rep_h)
                e["hits"]=rep_h+1;e["last"]=datetime.now().isoformat()
                e["maxtier"]=max(e.get("maxtier",0),tier)
                h=hist.setdefault(r["ip"],{"first_seen":datetime.now().isoformat(),
                    "total_alerts":0,"scan":0,"ssh":0,"icmp":0,"flood":0,"lateral":0,
                    "max_tier":0,"times_blocked":0,"attack_counts":{},
                    "iso_ever":False,"ml_used_ever":False,"best_band":"NORMAL","best_conf":0})
                h["total_alerts"]+=r["alerts"];h["scan"]+=r["scan"];h["ssh"]+=r["ssh"]
                h["icmp"]+=r["icmp"];h["flood"]+=r["flood"];h["lateral"]+=r["lat"]
                h["max_tier"]=max(h["max_tier"],tier);h["last_seen"]=datetime.now().isoformat()
                if anom:h["iso_ever"]=True
                if ml_used:h["ml_used_ever"]=True
                h["best_conf"]=max(h.get("best_conf",0),conf)
                order={"NORMAL":0,"SUSPICIOUS":1,"HIGH":2,"EXTREME":3}
                if order.get(band,0)>order.get(h.get("best_band","NORMAL"),0):h["best_band"]=band
                merge_counter(h,r["typecount"])
                if tier>=3 and r["ip"] not in ALLOWLIST_HOSTS:
                    with _state_lock:
                        already=r["ip"] in active_blocks
                    if not already:
                        tl=r["typelist"]
                        if tier>=4: target="any"
                        elif "LATERAL_HR" in tl: target="192.168.20.0 0.0.0.255"
                        elif "LATERAL_DMZ" in tl: target=f"{DMZ} 0.0.0.255"
                        else: target=f"{DMZ} 0.0.0.255"
                        scope,seq=enforce(r["ip"],tier,target)
                        if scope:
                            with _state_lock:
                                active_blocks[r["ip"]]={"tier":tier,"expires":time.time()+TTL_SECONDS,
                                    "scope":scope,"seq":seq,"target":target}
                            h["times_blocked"]+=1
                            print(f" [ENF] queued {r['ip']} tier{tier} -> {scope} [{target}] ({reason})")
                mlnote=" [ML-escalated]" if ml_used else ""
                print(f"  {r['ip']:<15} T{tier} conf={conf}% ml={band}({score:.2f}) "
                      f"rep={rep_h:.1f} action={action} :: {reason}{mlnote}")
                det=", ".join(f"{ATTACK_NAMES.get(k,k)} x{v}"
                              for k,v in sorted(r["typecount"].items(),key=lambda x:-x[1]))
                print(f"      DETECTED: {det}")
                print(f"      -> {expl}")
            _save(REP,rep);_save(HIST,hist)
        else:print("  no new alerts")
        print_block_state()
        out=[]
        for ip,h in hist.items():
            with _state_lock:
                blk=ip in active_blocks
                scope=active_blocks.get(ip,{}).get("scope","")
            allow=ip in ALLOWLIST_HOSTS
            counts=h.get("attack_counts",{})
            typelist=", ".join(f"{k}:{v}" for k,v in sorted(counts.items(),key=lambda x:-x[1]))
            out.append({"src_ip":ip,"alert_count":h["total_alerts"],"tier":h["max_tier"],
                "iso_anomaly":h.get("iso_ever",False),"ml_band":h.get("best_band","NORMAL"),
                "ml_used":h.get("ml_used_ever",False),"confidence":h.get("best_conf",0),
                "rate_limited":blk,"attack_types":typelist,"attack_counts":counts,
                "vlans_touched":1+sum(1 for k in counts if "LATERAL" in k),
                "scan":h["scan"],"ssh":h["ssh"],"icmp":h["icmp"],"flood":h["flood"],
                "lateral":h["lateral"],
                "reputation_hits":round(decayed_hits(rep.get(ip,{})),1),
                "blocked":blk,"block_scope":scope,
                "times_blocked":h["times_blocked"],"first_seen":h["first_seen"],
                "allowlisted":allow,"watchlist":(h["max_tier"] in (1,2) and not blk and not allow)})
        _save(OUT,out)
        cyc+=1;time.sleep(INTERVAL)

if __name__=="__main__":run()

"""Generate realistic multi-vendor synthetic perimeter logs for LOGFORGE demo."""
import os
import random
from datetime import datetime, timedelta, timezone

DATASET_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sample_logs")
os.makedirs(DATASET_DIR, exist_ok=True)

IPS = [
    "192.168.1.105", "10.0.4.15", "172.16.2.88", "192.168.50.21", 
    "203.0.113.45", "198.51.100.12", "8.8.8.8", "1.1.1.1", 
    "185.220.101.5", "45.33.32.156", "10.200.1.50", "192.168.1.1"
]

PORTS = [80, 443, 22, 53, 8080, 8443, 3389, 500, 4500, 25, 123]
PROTOCOLS = ["TCP", "UDP", "ICMP"]
ACTIONS = ["allow", "deny", "drop", "alert", "reset"]


def generate_all_samples():
    base_time = datetime.now(timezone.utc) - timedelta(hours=2)

    # 1. Palo Alto Syslog Logs (1,500 lines)
    palo_path = os.path.join(DATASET_DIR, "firewall_paloalto.log")
    with open(palo_path, "w", encoding="utf-8") as f:
        for i in range(1500):
            t = (base_time + timedelta(seconds=i * 3)).strftime("%b %d %H:%M:%S")
            src_ip = random.choice(IPS)
            dst_ip = random.choice(IPS)
            src_port = random.choice(PORTS)
            dst_port = random.choice(PORTS)
            proto = random.choice(["tcp", "udp", "icmp"])
            act = random.choice(["allow", "deny", "drop"])
            line = f"<14>1 {base_time.strftime('%Y-%m-%dT%H:%M:%SZ')} PA-5220-FW01 1 2026/09/28 TRAFFIC - - - src={src_ip} dst={dst_ip} sport={src_port} dport={dst_port} proto={proto} action={act} bytes_sent={random.randint(100, 10000)} bytes_received={random.randint(200, 50000)}"
            f.write(line + "\n")

    # 2. Cisco ASA Syslog Logs (1,200 lines)
    cisco_path = os.path.join(DATASET_DIR, "firewall_cisco_asa.log")
    with open(cisco_path, "w", encoding="utf-8") as f:
        for i in range(1200):
            t = (base_time + timedelta(seconds=i * 4)).strftime("%b %d %H:%M:%S")
            src_ip = random.choice(IPS)
            dst_ip = random.choice(IPS)
            src_port = random.choice(PORTS)
            dst_port = random.choice(PORTS)
            proto = random.choice(["tcp", "udp"])
            act = random.choice(["Deny", "Built", "Teardown"])
            sev = 4 if act == "Deny" else 6
            code = "106023" if act == "Deny" else "302013"
            line = f"<164>{t} cisco-asa-edge : %ASA-{sev}-{code}: {act} {proto} src outside:{src_ip}/{src_port} dst inside:{dst_ip}/{dst_port} by access-group \"outside_access_in\""
            f.write(line + "\n")

    # 3. Perimeter CEF Logs (1,000 lines)
    cef_path = os.path.join(DATASET_DIR, "perimeter_cef.log")
    with open(cef_path, "w", encoding="utf-8") as f:
        for i in range(1000):
            src_ip = random.choice(IPS)
            dst_ip = random.choice(IPS)
            src_port = random.choice(PORTS)
            dst_port = random.choice(PORTS)
            act = random.choice(["allow", "block", "drop"])
            sev = random.choice(["3", "5", "8", "10"])
            line = f"CEF:0|CheckPoint|SmartDefense|R81.20|threat:401|Packet dropped by rule|{sev}|src={src_ip} dst={dst_ip} spt={src_port} dpt={dst_port} proto=TCP act={act} msg=External attack probe blocked"
            f.write(line + "\n")

    # 4. VPN Gateway CSV Logs (800 lines)
    vpn_path = os.path.join(DATASET_DIR, "vpn_gateway.csv")
    with open(vpn_path, "w", encoding="utf-8") as f:
        f.write("timestamp,vendor,device_type,src_ip,dst_ip,src_port,dst_port,proto,action,user,status\n")
        for i in range(800):
            iso_t = (base_time + timedelta(seconds=i * 5)).isoformat()
            src_ip = random.choice(IPS)
            dst_ip = "10.0.0.1"
            act = random.choice(["allow", "deny"])
            user = random.choice(["admin", "esamb", "svc_backup", "analyst_1", "vpn_guest"])
            f.write(f"{iso_t},PulseSecure,vpn,{src_ip},{dst_ip},443,443,TCP,{act},{user},tunnel_active\n")

    # 5. Suricata IDS EVE JSON (1,000 lines)
    ids_path = os.path.join(DATASET_DIR, "ids_suricata.json")
    with open(ids_path, "w", encoding="utf-8") as f:
        for i in range(1000):
            iso_t = (base_time + timedelta(seconds=i * 6)).isoformat()
            src_ip = random.choice(IPS)
            dst_ip = random.choice(IPS)
            src_port = random.choice(PORTS)
            dst_port = random.choice(PORTS)
            act = random.choice(["alert", "drop", "allow"])
            proto = random.choice(["TCP", "UDP"])
            line = f'{{"timestamp":"{iso_t}","event_type":"alert","src_ip":"{src_ip}","dest_ip":"{dst_ip}","src_port":{src_port},"dest_port":{dst_port},"proto":"{proto}","action":"{act}","alert":{{"signature":"ET EXPLOIT Suspicious Perimeter Scan","severity":2}}}}'
            f.write(line + "\n")

    # 6. LEEF Format Logs (500 lines)
    leef_path = os.path.join(DATASET_DIR, "leef_perimeter.log")
    with open(leef_path, "w", encoding="utf-8") as f:
        for i in range(500):
            src_ip = random.choice(IPS)
            dst_ip = random.choice(IPS)
            src_port = random.choice(PORTS)
            dst_port = random.choice(PORTS)
            act = random.choice(["allow", "blocked"])
            line = f"LEEF:1.0|Fortinet|FortiGate|7.0|10203|\tsrc={src_ip}\tdst={dst_ip}\tspt={src_port}\tdpt={dst_port}\tproto=6\tact={act}\tdevname=FGT-EDGE-01"
            f.write(line + "\n")

    # 7. Malformed Edge Cases (10 lines to demonstrate quarantine and failure handling)
    malformed_path = os.path.join(DATASET_DIR, "malformed_edge_cases.log")
    with open(malformed_path, "w", encoding="utf-8") as f:
        f.write("Corrupted unparseable raw gibberish without any format 12345\n")
        f.write("{invalid_json_missing_quote: true}\n")
        f.write("CEF:invalid_too_few_pipes|only|two\n")
        f.write("<99999>Invalid syslog priority number\n")
        f.write("Random console debug statement: kernel panic at memory address 0x00000000\n")


if __name__ == "__main__":
    generate_all_samples()
    print("All synthetic demonstration datasets generated successfully!")

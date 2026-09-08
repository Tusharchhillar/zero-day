"""Generate demo JSONL fixtures for each attack type + a mixed scenario."""
import json
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path


def _ts(t: float) -> str:
    """Seconds since epoch → ISO-8601 UTC string."""
    return datetime.fromtimestamp(t, tz=timezone.utc).isoformat()


def _event(t, src, dst, proto, **kw):
    return json.dumps({"timestamp": _ts(t), "src_ip": src, "dst_ip": dst, "protocol": proto, **kw})


def gen_ddos(out: Path, duration: float = 30.0):
    """SYN flood: many sources → one dest."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(42)
    t = t0
    while t < t0 + duration:
        t += rng.expovariate(200)
        if t >= t0 + duration:
            break
        src = f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
        events.append(_event(t, src, "192.168.1.100", "tcp",
                             dst_port=443, packets_src_to_dst=1,
                             bytes_src_to_dst=64, bytes_dst_to_src=0,
                             flow_id=f"flood-{rng.randint(0,9999)}"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_beacon(out: Path, duration: float = 60.0):
    """C2 beacon: periodic connections every 5s with tiny jitter."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(52)
    t = t0
    while t < t0 + duration:
        t += 5.0 + rng.gauss(0, 0.02)
        if t >= t0 + duration:
            break
        events.append(_event(t, "10.0.0.50", "185.234.72.10", "tcp",
                             dst_port=443, packets_src_to_dst=1,
                             bytes_src_to_dst=128, bytes_dst_to_src=64,
                             flow_id="beacon-cc"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_dga(out: Path, duration: float = 20.0):
    """DGA domains: random strings as DNS queries."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(62)
    t = t0
    while t < t0 + duration:
        t += rng.expovariate(5)
        if t >= t0 + duration:
            break
        label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20))
        suffix = rng.choice([".com", ".net", ".org", ".ru", ".cn"])
        events.append(_event(t, "10.0.0.60", "8.8.8.8", "dns",
                             dns_query=f"{label}{suffix}", dns_query_type="A",
                             flow_id=f"dga-{rng.randint(0,9999)}"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_dns_tunnel(out: Path, duration: float = 20.0):
    """DNS tunnelling: long queries, high entropy, rapid."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(72)
    t = t0
    while t < t0 + duration:
        t += rng.expovariate(20)
        if t >= t0 + duration:
            break
        payload = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=60))
        events.append(_event(t, "10.0.0.70", "8.8.8.8", "dns",
                             dns_query=f"{payload}.tunnel.example.com",
                             dns_query_type="TXT", dst_port=53,
                             bytes_src_to_dst=128, bytes_dst_to_src=512,
                             flow_id=f"tunnel-{rng.randint(0,9999)}"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_port_scan(out: Path, duration: float = 10.0):
    """Port scan: one source → many ports on one dest."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(82)
    t = t0
    for port in range(1, 200):
        t += rng.expovariate(50)
        if t >= t0 + duration:
            break
        events.append(_event(t, "10.0.0.80", "192.168.1.200", "tcp",
                             dst_port=port, packets_src_to_dst=1,
                             bytes_src_to_dst=60, bytes_dst_to_src=0,
                             flow_id=f"scan-{port}"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_exfil(out: Path, duration: float = 20.0):
    """Data exfiltration: large outbound bursts."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(92)
    t = t0
    while t < t0 + duration:
        t += rng.expovariate(3)
        if t >= t0 + duration:
            break
        size = rng.randint(1000, 1400)
        events.append(_event(t, "10.0.0.90", "203.0.113.50", "tcp",
                             dst_port=443, packets_src_to_dst=1,
                             bytes_src_to_dst=size, bytes_dst_to_src=0,
                             flow_id="exfil-cc"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_encrypted_c2(out: Path, duration: float = 30.0):
    """Encrypted C2: uniform 512B packets, regular 0.5s timing."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(102)
    t = t0
    while t < t0 + duration:
        t += 0.5 + rng.gauss(0, 0.01)
        if t >= t0 + duration:
            break
        events.append(_event(t, "10.0.0.40", "198.51.100.77", "tls",
                             dst_port=443, packets_src_to_dst=1,
                             bytes_src_to_dst=512, bytes_dst_to_src=512,
                             tls_version="TLS 1.3", sni="updates-cdn.example.com",
                             flow_id="c2-encrypted"))
    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events")


def gen_mixed(out: Path, duration: float = 120.0):
    """Combined scenario: benign baseline + inject each attack type at different times."""
    t0 = 1700000000.0
    events = []
    rng = random.Random(77)

    # Benign traffic throughout
    t = t0
    while t < t0 + duration:
        t += rng.expovariate(3)
        if t > t0 + duration:
            break
        events.append(_event(t, f"10.0.{rng.randint(1,5)}.{rng.randint(1,100)}",
                             "192.168.1.1", "tcp",
                             dst_port=rng.choice([80, 443, 8080]),
                             packets_src_to_dst=rng.randint(1, 10),
                             bytes_src_to_dst=rng.randint(60, 1400),
                             bytes_dst_to_src=rng.randint(60, 1400),
                             flow_id=f"benign-{rng.randint(0,9999)}"))

    # SYN flood at t+10s
    for i in range(80):
        t_flood = t0 + 10.0 + rng.expovariate(200)
        src = f"{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}.{rng.randint(1,254)}"
        events.append(_event(t_flood, src, "192.168.1.100", "tcp",
                             dst_port=443, packets_src_to_dst=1,
                             bytes_src_to_dst=64, bytes_dst_to_src=0,
                             flow_id="flood-mixed"))

    # Port scan at t+30s
    for port in range(1, 50):
        t_scan = t0 + 30.0 + rng.expovariate(50)
        events.append(_event(t_scan, "10.0.0.80", "192.168.1.200", "tcp",
                             dst_port=port, packets_src_to_dst=1,
                             bytes_src_to_dst=60, bytes_dst_to_src=0,
                             flow_id=f"scan-mixed-{port}"))

    # DGA at t+50s
    for _ in range(30):
        t_dga = t0 + 50.0 + rng.expovariate(5)
        label = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=20))
        events.append(_event(t_dga, "10.0.0.60", "8.8.8.8", "dns",
                             dns_query=f"{label}.ru", dns_query_type="A",
                             flow_id="dga-mixed"))

    # Beacon at t+70s
    for i in range(15):
        t_beacon = t0 + 70.0 + i * 5.0 + rng.gauss(0, 0.02)
        events.append(_event(t_beacon, "10.0.0.50", "185.234.72.10", "tcp",
                             dst_port=443, packets_src_to_dst=1,
                             bytes_src_to_dst=128, bytes_dst_to_src=64,
                             flow_id="beacon-mixed"))

    events.sort(key=lambda e: json.loads(e)["timestamp"])

    with open(out, "w") as f:
        f.write("\n".join(events) + "\n")
    print(f"  {out.name}: {len(events)} events (mixed scenario)")


if __name__ == "__main__":
    outdir = Path("data/fixtures")
    outdir.mkdir(parents=True, exist_ok=True)

    print("Generating demo fixtures...")
    gen_ddos(outdir / "syn_flood.jsonl")
    gen_beacon(outdir / "c2_beacon.jsonl")
    gen_dga(outdir / "dga_domains.jsonl")
    gen_dns_tunnel(outdir / "dns_tunnel.jsonl")
    gen_port_scan(outdir / "port_scan.jsonl")
    gen_exfil(outdir / "data_exfil.jsonl")
    gen_encrypted_c2(outdir / "encrypted_c2.jsonl")
    gen_mixed(outdir / "full_scenario.jsonl")
    print("Done.")

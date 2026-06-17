import json
from enum import Enum
from probe import get_pem_certificate
from parser import parse_certificate
from analyzer import analyze, severity, Status

TARGETS_FILE = "targets.txt"
OUTPUT_FILE  = "output.json"


class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.value
        return super().default(obj)


def load_targets(path):
    targets = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else 443
            targets.append((host, port))
    return targets


def scan_target(host, port):
    pem   = get_pem_certificate(host, port)
    cert  = parse_certificate(pem)
    flags = analyze(cert)
    return {
        "host":        host,
        "port":        port,
        "status":      Status.OK,
        "severity":    severity(flags),
        "flags":       flags,
        "certificate": cert,
    }


def main():
    targets = load_targets(TARGETS_FILE)
    results = []

    for host, port in targets:
        print(f"Scanning {host}:{port} ...", end=" ")
        try:
            result = scan_target(host, port)
            print(result["severity"].value)
        except Exception as e:
            result = {
                "host":   host,
                "port":   port,
                "status": Status.ERROR,
                "error":  str(e),
            }
            print(f"ERROR — {e}")
        results.append(result)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2, cls=EnumEncoder)

    print(f"\nDone. {len(results)} targets scanned → {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
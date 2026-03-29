# PortScan 

A fast, multithreaded random port scanner with service fingerprinting, risk classification, and banner grabbing.

> ⚠️ Use only on systems you own or have explicit permission to test.

---

## Features

- **Randomized scanning** — shuffles ports before scanning to avoid pattern-based detection
- **Multithreaded** — up to 300 concurrent threads for fast sweeps
- **Service fingerprinting** — identifies 50+ known services by port number
- **Risk classification** — flags ports as `HIGH-RISK`, `ELEVATED`, or `INFO`
- **Banner grabbing** — optionally pulls service banners from open ports
- **Progress bar** — live scan progress with percentage and port count
- **Save results** — export findings to a timestamped `.txt` file
- **Color output** — ANSI-colored terminal output (disable with `--no-color`)

---

## Installation

No dependencies beyond the Python standard library.

```bash
git clone https://github.com/blaxkmiradev/Port-Scanner.git
cd Port-Scanner
python scanner.py
```

Requires **Python 3.10+**.

---

## Usage

### Interactive mode

```bash
python scanner.py
```

```
Enter target (IP/domain): 192.168.1.1
```

### CLI mode

```bash
python scanner.py 192.168.1.1
python scanner.py example.com -s 1 -e 1024 -w 200 -t 1.0 --banner
```

### All options

| Flag | Default | Description |
|---|---|---|
| `target` | — | IP address or hostname to scan |
| `-s, --start` | `1` | Port range start |
| `-e, --end` | `9999` | Port range end |
| `-w, --workers` | `150` | Concurrent threads |
| `-t, --timeout` | `0.8` | Timeout per port (seconds) |
| `-b, --banner` | off | Grab service banners |
| `--no-color` | off | Disable ANSI colors |

---

## Output

```
  [HIGH-RISK ]  :22      SSH
  [ELEVATED  ]  :3306    MySQL
  [INFO      ]  :80      HTTP
  [INFO      ]  :443     HTTPS   ↳ HTTP/1.1 200 OK
```

### Risk tiers

| Tier | Color | Ports |
|---|---|---|
| `HIGH-RISK` | Red | 21, 23, 135–139, 445, 1433, 3389, 5900 |
| `ELEVATED` | Yellow | 22, 25, 110, 143, 3306, 5432, 6379, 27017 |
| `INFO` | Green | Everything else |

---

## Examples

Scan common ports fast:
```bash
python scanner.py 10.0.0.1 -s 1 -e 1024 -w 250 -t 0.5
```

Full scan with banner grabbing:
```bash
python scanner.py 10.0.0.1 -e 9999 -b
```

Quiet output for scripting:
```bash
python scanner.py 10.0.0.1 --no-color > results.txt
```

---

## Legal

This tool is for authorized security testing only. Unauthorized port scanning may violate local laws and network terms of service. The author assumes no liability for misuse.

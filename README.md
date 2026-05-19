# VANGUARD

Vanguard is a Python-based reconnaissance utility that automates:

- port scanning using nmap,
- XML parsing,
- web service detection,
- directory fuzzing with ffuf.

---

# Features

- Automated nmap setup
- XML parsing of scan results
- Open-port listing with detected services
- Web-service detection based on ports and service names
- ffuf-based fuzzing against discovered HTTP/HTTPS targets
- Local `programs/` directory for downloaded dependencies

---

# Repository Structure

```text
.
├── .gitignore
├── install.py
├── launcher.py
├── main.py
└── programs/   # created locally after installation
```

## Files

### `install.py`
Downloads:
- portable nmap,
- ffuf,
- SecLists wordlist.

### `main.py`
Responsible for:
- running scans,
- parsing XML results,
- detecting web services,
- launching ffuf.

### `launcher.py`
Placeholder for future automation and orchestration features.

---

# Requirements

- Python 3
- Internet connection during setup
- Unix-like environment

---

# Installation

```bash
python install.py
```

This downloads all required tools into the local `programs/` directory.

---

# Usage

```bash
python main.py <target>
```

## Examples

```bash
python main.py 192.168.1.10
python main.py example.com
```

---

# Workflow

1. Run nmap scan
2. Parse XML output
3. Detect web targets
4. Generate URLs
5. Run ffuf fuzzing

---

# TODO

- [ ] Rewrite UI into a TUI using [axto](https://github.com/rioxpi/axto)
- [ ] Add ffuf output parser
- [ ] Add automated launcher
- [ ] Improve error handling
- [ ] Add custom wordlist support

---

# Disclaimer

This project is intended for educational purposes and authorized security testing only.
# VANGUARD

![Python](https://img.shields.io/badge/python-3.x-blue)
![Status](https://img.shields.io/badge/status-active-success)
![Platform](https://img.shields.io/badge/platform-linux-lightgrey)
![License](https://img.shields.io/badge/license-none-red)

Vanguard is a Python-based reconnaissance utility that automates:

- port scanning using nmap,
- XML parsing,
- web service detection,
- directory fuzzing with ffuf.
- Scanning headers

---

## Features

- Automated nmap setup
- XML parsing of scan results
- Open-port listing with detected services
- Web-service detection based on ports and service names
- ffuf-based fuzzing against discovered HTTP/HTTPS targets
- Local `programs/` directory for downloaded dependencies
- Aggressive nmap port scanning
- Text User Interface
- Analysing web headers

---

## Repository Structure

```text
.
├── .gitignore
├── install.py
├── launcher.py
├── core/
│   ├── config.py 
│   └── TUI.py
├── modules/
│   ├── port_scanner.py
│   ├── directory_fuzzer.py
│   └── web_analyzer.py
├── main.py
├── README.md
└── programs/   # created locally after installation
```

### Files

#### `install.py`

Downloads:
- portable nmap,
- ffuf,
- SecLists wordlist.

#### `main.py`

Responsible for:
- coordinating all modules
- running the full reconnaissance workflow

#### `config.py`

Contains default variables:
- web target ports and services
- directories for downloaded programs

### TUI.py

Responsible for:
- Text User Interface unsing axto library

#### `directory_fuzzer.py`

Responsible for:
- launching ffuf
- parsing ffuf output

#### `port_scanner.py`

Responsible for:
- launching nmap
- parsing nmap output

### `web_analyzer.py`

Responsible for:
- Analysing web headers

### `launcher.py`

Placeholder for future automation and orchestration features.

---

## Requirements

- Python 3
- Internet connection during setup
- Unix-like environment

---

## Installation

```bash
python install.py
```

This downloads all required tools into the local `programs/` directory.

---

## Usage

```bash
python main.py <target>
```

### Examples

```bash
python main.py 192.168.1.10
python main.py example.com
```

---

## Workflow

1. Run nmap scan
2. Parse XML output
3. Detect web targets
4. Generate URLs
5. Run ffuf fuzzing

---

## TODO

- [X] Rewrite UI into a TUI using [axto](https://github.com/rioxpi/axto)
- [X] Add ffuf output parser
- [ ] Add automated launcher
- [ ] Improve error handling
- [ ] Add custom wordlist support
- [X] Add Agressive port scanning

---

## CHANGELOG

### VERSION 0.0.1

1. Add port scanning using nmap
2. Add directory fuzzing using ffuf
3. Parsing nmap&ffuf oputput

### VERSION 0.1.0

1. Add UI using Axto library
2. Add web headers analyser
3. Add aggressive nmap port scanning

---

## Disclaimer

This project is intended for educational purposes and authorized security testing only.

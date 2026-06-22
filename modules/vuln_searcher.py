import json 
import subprocess
import xml.etree.ElementTree as ET
from core.config import DIRECTORIES

class VulnSearcher:
    def __init__(self) -> None:
            pass
    def search_for_exploits(self, services: list):
        data = []
        for s in services:
            out = self._scan_software_version(s[0], s[1])
            data.extend(self._parse_output(out))
        
        return data     

    def _scan_software_version(self, product, version):
        print(f"Data: {product}, {version}")
        query = f"{product} {version}".strip()
        print(f"Searching for {query}")
        
        cmd = [DIRECTORIES['searchsploit'], query, '--json']
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except FileNotFoundError:
            raise FileNotFoundError(
                "searchsploit is not installed. Please run install.py to download"
            )
        except Exception as e:
            raise Exception(f"An error  occurred while running nmap: {e}")
        
    def _parse_output(self, raw_data: str) -> list:
        if raw_data.strip():
            data = json.loads(raw_data)
            
            exploits = data.get("RESULTS_EXPLOIT", [])
            
            findings = []
            
            for e in exploits:
                findings.append({
                    'title' : e.get("Title"),
                    'type' : e.get("Type"),
                    'platform' : e.get("Platform"),
                    'exploit_id' : e.get("EDB-ID"),
                    'path' : e.get("Path")
                })
            return findings

        return []
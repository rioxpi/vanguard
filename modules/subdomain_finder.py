import subprocess
import socket
import requests
from urllib3.exceptions import InsecureRequestWarning
from core.config import DIRECTORIES

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class SubdomainFinder:
    def fetch_subdomains(self, domain):
        """Fetches subdomains from crt.sh for the given domain.

        Args:
            domain (str): The target domain to search for subdomains.
        Returns:
            list: A list of subdomains found for the target domain.
        """
        subdomains = set()
        clean_domain = domain.strip().lower()
        
        cmd = [DIRECTORIES["subfinder"], "-d", clean_domain, "-silent"]

        try:
            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.DEVNULL, 
                text=True
            )

            for line in process.stdout:
                subdomain = line.strip().lower()
                if subdomain and not subdomain.startswith("*") and subdomain.endswith(clean_domain):
                    subdomains.add(subdomain)

            process.wait(timeout=60)
            
        except subprocess.TimeoutExpired:
            process.kill()
            print("[!] Timeout: Subfinder przekroczył limit czasu (60s).")
        except Exception as e:
            print(f"[!] Wystąpił nieoczekiwany błąd: {e}")

        return list(subdomains)
    
    def validate_subdomain(self, subdomains: list) -> dict:
        """Validates the list of subdomains by checking if they resolve to an IP address.

        Args:
            subdomains (list): A list of subdomains to validate.
        Returns:
            dict: A dictionary of validated subdomains with their IP addresses.
        """
        active_subdomains = {}
        
        for subdomain in subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                active_subdomains[subdomain] = ip
            except socket.gaierror:
                continue
        
        if not active_subdomains:
            return {"error": "No active subdomains found!"}
        return active_subdomains

    def get_subdomains(self, domain: str) -> dict:
        """Main method to fetch and validate subdomains for the target domain."""
        subdomains = self.fetch_subdomains(domain)
        if isinstance(subdomains, list) and subdomains and not subdomains[0].startswith("crt.sh returned status code"):
            validated_subdomains = self.validate_subdomain(subdomains)
            return validated_subdomains
        else:
            return {"error": "No subdomains found or an error occurred while fetching from crt.sh."}
import subprocess
import sys
import xml.etree.ElementTree as ET
from core.config import DIRECTORIES


class PortScanner:
    """A class to handle port scanning using nmap and parsing the results."""

    def run_scan(self, target: str) -> dict:
        """Runs the nmap scan and processes the results.

        Args:
            target (str): The target to scan
        """
        xml_output = self.run_nmap(target)
        open_ports = self.parse_nmap_xml(xml_output)

        return open_ports

    def run_nmap(self, target: str) -> str:
        """Runs nmap against the specified target and returns the XML output as a string.

        Args:
            target (str): The target to scan

        Returns:
            str: The XML output from nmap as a string.
        """
        try:
            result = subprocess.run(
                [DIRECTORIES["nmap"], "-F", "-oX", "-", target],
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout
        except FileNotFoundError:
            raise FileNotFoundError(
                "nmap is not installed. Please run install.py to download and set up nmap."
            )
            sys.exit(1)
        except Exception as e:
            raise Exception(f"An error occurred while running nmap: {e}")
            sys.exit(1)

    def parse_nmap_xml(self, xml_data: str) -> dict:
        """Parses the nmap XML output and extracts open ports

        Args:
            xml_data (str): The XML output from nmap as a string.

        Returns:
            dict: A dictionary of open ports and their services.
        """
        open_ports = {}
        try:
            root = ET.fromstring(xml_data)
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    port_id = port.get("portid")
                    service = port.find("service")
                    service_name = (
                        service.get("name") if service is not None else "unknown"
                    )
                    open_ports[port_id] = service_name
        except ET.ParseError as e:
            raise Exception(f"Error parsing XML: {e}")

        return open_ports

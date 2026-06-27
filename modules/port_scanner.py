import subprocess
import sys
import xml.etree.ElementTree as ET
from core.config import DIRECTORIES, NMAP_CONFIG


class PortScanner:
    """A class to handle port scanning using nmap and parsing the results."""

    def quick_scan(self, target: str) -> dict:
        """Runs the nmap scan and processes the results.

        Args:
            target (str): The target to scan
        """
        xml_output = self.run_nmap(target)
        open_ports = self.parse_nmap_xml(xml_output)

        return open_ports

    def full_scan(self, target: str, ports: list[str]) -> str:
        """Runs nmap aggressive scan

        Args:
            ports (list[str]): open ports from quick scan

        Returns:
            dict: data
        """
        if not ports:
            return ""

        ports_str = ",".join(ports)

        cmd = [
            DIRECTORIES["nmap"],
            "-p",
            ports_str,
            "-A",
            NMAP_CONFIG["aggressive_level"],
            "-Pn",
            "-oX",
            "-",
            target,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout

    def run_nmap(self, target: str) -> str:
        """Runs nmap against the specified target and returns the XML output as a string.

        Args:
            target (str): The target to scan

        Returns:
            str: The XML output from nmap as a string.
        """
        try:
            result = subprocess.run(
                [DIRECTORIES["nmap"], NMAP_CONFIG["port_flag"], "-oX", "-", target],
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

    def parse_nmap_aggressive_xml(self, xml_file):
        root = ET.fromstring(xml_file)

        report = {}

        for host in root.findall("host"):
            status_el = host.find("status")
            status = status_el.get("state") if status_el is not None else "unknown"
            if status != "up":
                continue

            # IP & MAC
            ip_address = None
            mac_address = None
            for addr in host.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4":
                    ip_address = addr.get("addr")
                elif addr_type == "mac":
                    mac_address = addr.get("addr")

            if not ip_address:
                continue

            report[ip_address] = {
                "mac": mac_address if mac_address else "",
                "hostnames": [],
                "ports": [],
                "os_matches": [],
            }

            # Hostname
            hostnames_el = host.find("hostnames")
            if hostnames_el is not None:
                for hn in hostnames_el.findall("hostname"):
                    report[ip_address]["hostnames"].append(hn.get("name"))

            # Ports
            ports_el = host.find("ports")
            if ports_el is not None:
                for port in ports_el.findall("port"):
                    state_el = port.find("state")

                    if state_el is not None and state_el.get("state") == "open":
                        service_name = "unknown"
                        full_version_string = "unknown"

                        service_el = port.find("service")
                        if service_el is not None:
                            service_name = service_el.get("name", "unknown")

                            prod = service_el.get("product", "").strip()
                            ver = service_el.get("version", "").strip()
                            ext = service_el.get("extrainfo", "").strip()

                            # Product version (extrainfo)
                            version_parts = []
                            if prod:
                                version_parts.append(prod)
                            if ver:
                                version_parts.append(ver)
                            if ext:
                                version_parts.append(f"({ext})")

                            if version_parts:
                                full_version_string = " ".join(version_parts)

                        scripts_list = []
                        for script in port.findall("script"):
                            scripts_list.append(
                                {
                                    "script_name": script.get("id", "").strip(),
                                    "script_output": script.get("output", "").strip(),
                                }
                            )

                        port_data = {
                            "portid": int(port.get("portid")),  # type: ignore
                            "protocol": port.get("protocol", "tcp"),
                            "service": service_name,
                            "version": full_version_string,
                            "scripts": scripts_list,
                        }

                        report[ip_address]["ports"].append(port_data)

            # OS Matches
            os_el = host.find("os")
            if os_el is not None:
                for os_match in os_el.findall("osmatch"):
                    report[ip_address]["os_matches"].append(
                        {
                            "name": os_match.get("name", "unknown"),
                            "accuracy": int(os_match.get("accuracy", 0)),
                        }
                    )

        return report

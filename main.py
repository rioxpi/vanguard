import subprocess
import sys
import xml.etree.ElementTree as ET

def run_nmap(target: str) -> str:
    """Runs nmap against the specified target and returns the XML output as a string.

    Args:
        target (str): The target to scan

    Returns:
        str: The XML output from nmap as a string.
    """
    try:
        result = subprocess.run(['programs/nmap/run-nmap.sh', '-F', '-oX', '-', target], capture_output=True, text=True, check=True)
        return result.stdout
    except FileNotFoundError:
        print("nmap is not installed. Please run install.py to download and set up nmap.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")
        sys.exit(1)

def parse_nmap_xml(xml_data: str) -> dict:
    """Parses the nmap XML output and extracts open ports

    Args:
        xml_data (str): The XML output from nmap as a string.

    Returns:
        dict: A dictionary of open ports and their services.
    """
    print("Parsing nmap XML output...")
    open_ports = {}
    try:
        root = ET.fromstring(xml_data)
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                port_id = port.get('portid')
                service = port.find('service')
                service_name = service.get('name') if service is not None else 'unknown'
                open_ports[port_id] = service_name
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
    
    return open_ports

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Running nmap against target: {target}")
    xml_output = run_nmap(target)
    open_ports = parse_nmap_xml(xml_output)

    if open_ports:
        print("Open ports found:")
        for port, service in open_ports.items():
            print(f"{port}: {service}")
    else:
        print("No open ports found.")

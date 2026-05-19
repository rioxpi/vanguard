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
        result = subprocess.run(['nmap', '-F', '-oX', '-', target], capture_output=True, text=True, check=True)
        return result.stdout
    except FileNotFoundError:
        print("nmap is not installed or not found in PATH. Please install nmap and try again.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while running nmap: {e}")
        sys.exit(1)

def parse_nmap_xml(xml_data: str) -> list:
    """Parses the nmap XML output and extracts open ports

    Args:
        xml_data (str): The XML output from nmap as a string.

    Returns:
        list: A list of open ports.
    """
    print("Parsing nmap XML output...")
    open_ports = []
    try:
        root = ET.fromstring(xml_data)
        for port in root.findall('.//port'):
            state = port.find('state')
            if state is not None and state.get('state') == 'open':
                port_id = port.get('portid')
                service = port.find('service')
                service_name = service.get('name') if service is not None else 'unknown'
                open_ports.append(f"{port_id}/{service_name}")
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
        for port in open_ports:
            print(port)
    else:
        print("No open ports found.")
import json
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

def parse_ffuf_json(json_data: str) -> list:
    """Parses the ffuf JSON output and extracts found URLs.

    Args:
        json_data (str): The JSON output from ffuf as a string.

    Returns:
        list: A list of found URLs.
    """
    print("Parsing ffuf JSON output...")
    found_urls = []
    try:
        data = json.loads(json_data)
        for result in data.get('results', []):
            url = result.get('url')
            if url:
                found_urls.append(url)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON: {e}")
    
    return found_urls

def run_ffuf(target: str) -> None:
    """Runs ffuf against the specified target.

    Args:
        target (str): The target to scan
    """
    try:
        subprocess.run(['programs/ffuf/ffuf', '-u', f'{target}/FUZZ', '-w', 'programs/wordlist.txt', '-o', 'ffuf_output.json', '-of', 'json'], check=True, capture_output=True, text=True)
    except FileNotFoundError:
        print("ffuf is not installed. Please run install.py to download and set up ffuf.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred while running ffuf: {e}")
        sys.exit(1)

if __name__ == "__main__":
    SSL_SERVICES = {"https", "ssl/http", "https-alt", "ssl/https"}
    PLAIN_HTTP_SERVICES = {"http", "http-alt", "jetty", "apache-tomcat", "nginx", "lighttpd", "http-proxy"}
    
    SSL_PORTS = {"443", "8443", "9443"}
    PLAIN_HTTP_PORTS = {"80", "3000", "5000", "8000", "8080", "8081", "8088", "8888", "9000"}
    if len(sys.argv) != 2:
        print("Usage: python main.py <target>")
        sys.exit(1)

    target = sys.argv[1]
    print(f"Running nmap against target: {target}")
    xml_output = run_nmap(target)
    open_ports = parse_nmap_xml(xml_output)

    if open_ports:
        web_targets = {}
        print("Open ports found:")
        for port, service in open_ports.items():
            print(f"{port}: {service}")

            if service in SSL_SERVICES or port in SSL_PORTS:
                web_targets[port] = f"https://{target}:{port}"
            elif service in PLAIN_HTTP_SERVICES or port in PLAIN_HTTP_PORTS:
                web_targets[port] = f"http://{target}:{port}"
    
        if web_targets:
            print("\nWeb targets identified:")
            for port, url in web_targets.items():
                print(f"{port}: {url}")
            
            for port, url in web_targets.items():
                print(f"\nRunning ffuf against {url}...")
                run_ffuf(url)
                print(f"Parsing ffuf results for {url}...")
                parsed_results = parse_ffuf_json(open('ffuf_output.json').read())
                for found_url in parsed_results:
                    print(f"Found URL: {found_url}")
        
    else:
        print("No open ports found.")

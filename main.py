import os
import sys
import xml.etree.ElementTree as ET
from modules.port_scanner import PortScanner
from modules.directory_fuzzer import DirectoryFuzzer
from core.config import PLAIN_HTTP_PORTS, PLAIN_HTTP_SERVICES, SSL_PORTS, SSL_SERVICES

def main():

    target = sys.argv[1]
    port_scanner = PortScanner()
    open_ports = port_scanner.run_scan(target)

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
            
            directory_fuzzer = DirectoryFuzzer()
            for port, url in web_targets.items():
                print(f"\nRunning ffuf against {url}...")
                parsed_results = directory_fuzzer.start_fuzzing(url)
                for found_url in parsed_results:
                    print(f"Found URL: {found_url}")
                os.remove('ffuf_output.json')
        
    else:
        print("No open ports found.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <target>")
        sys.exit(1)
    main()


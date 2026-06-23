import os
from modules.port_scanner import PortScanner
from modules.directory_fuzzer import DirectoryFuzzer
from modules.web_analyzer import WebAnalyzer
from modules.subdomain_finder import SubdomainFinder
from modules.ftp_spider import FtpSpider
from modules.save_data import DataSaver
from modules.vuln_searcher import VulnSearcher
from core.config import PLAIN_HTTP_PORTS, PLAIN_HTTP_SERVICES, SSL_PORTS, SSL_SERVICES, ACTIVE_MODULES, NMAP_CONFIG
from concurrent.futures import ThreadPoolExecutor
from core.TUI import TUI
import threading

class Vanguard:
    """The main class for the Vanguard application, orchestrating all processes."""

    def __init__(self):
        self.port_scanner = PortScanner()
        self.directory_fuzzer = DirectoryFuzzer()
        self.web_analyzer = WebAnalyzer()
        self.subdomain_finder = SubdomainFinder()
        self.ftp_spider = FtpSpider()
        self.data_saver = DataSaver()
        self.vuln_searcher = VulnSearcher()
        self.tui_app = TUI(self)
        self.target = ""

    def run(self):
        self.tui_app.run()

    def set_target(self, target: str):
        self.target = target
        scan_thread = threading.Thread(
            target=self._scan_worker, 
            args=(target,),
            daemon=True
        )
        scan_thread.start()

    def _scan_worker(self, target: str):
        open_ports = self.port_scanner.quick_scan(target)
        
        if open_ports:
            web_targets = self.identify_web_targets(open_ports)
            subdomain_results = {}
            
            with ThreadPoolExecutor(max_workers=3) as executor:
                # RUNNING EXECUTORS
                
                # NMAP AGGRESSIVE
                if ACTIVE_MODULES["nmap_aggressive"]:
                    future_aggressive_scan = executor.submit(self.run_port_scanner_aggressive, open_ports)
                
                # FFUF
                if ACTIVE_MODULES["ffuf"]:
                    future_fuzzing = executor.submit(self.run_directory_fuzzer, web_targets)
                    
                    # WEB ANALYZER
                    if ACTIVE_MODULES['web_analyzer']:
                        future_web_analysis = executor.submit(self.run_web_analysis, list(web_targets.values()))
                
                # SUBDOMAIN
                if ACTIVE_MODULES['subdomain']:
                    future_subdomain_finding = executor.submit(self.subdomain_finder.find_subdomains, target)
                
                # FTP
                if '21' in open_ports and ACTIVE_MODULES['ftp']: 
                    future_ftp_spider = executor.submit(self.ftp_spider.scan, target)
                
                
                # READING DATA
                
                # NMAP AGGRESSIVE
                if ACTIVE_MODULES["nmap_aggressive"]:
                    aggressive_port_scan = future_aggressive_scan.result()
                    
                    found_vulnerabilities = []
                    services_to_scan = []
                    for ip, host_data in aggressive_port_scan.items():
                        for data in host_data['ports']:
                            if data['version'] != "unknown":
                                d = data["version"].split(" ")
                                services_to_scan.append([d[0], d[1]])
                        
                    found_vulnerabilities = self.vuln_searcher.search_for_exploits(services_to_scan)
                else:
                    aggressive_port_scan = {}
                    found_vulnerabilities = []

                # FFUF
                if ACTIVE_MODULES["ffuf"]:
                    fuzzing_results = future_fuzzing.result()
                    if ACTIVE_MODULES['web_analyzer']:
                        web_analysis_results = future_web_analysis.result()
                    else:
                        web_analysis_results = {"warning" : "THIS MODULE IS DISABLED"}
                else:
                    fuzzing_results = ["THIS MODULE IS DISABLED"]
                    web_analysis_results = {}
                
                # FTP
                if '21' in open_ports and ACTIVE_MODULES['FTP']:
                    ftp_spider = future_ftp_spider.result()
                else:                    
                    ftp_spider = ['Port 21 is not open or this module is disabled']
                
                # SUBDOMAIN
                if ACTIVE_MODULES['subdomain']:
                    subdomain_results = future_subdomain_finding.result()
                else:
                    subdomain_results = {"THIS MODULE IS DISABLED"}
        else:
            open_ports = {"WARNING" : "Host has no open ports"}
            fuzzing_results = ["Nothing to show!"]
            web_analysis_results = {}
            aggressive_port_scan = {}
            subdomain_results = {}
            ftp_spider = []
            found_vulnerabilities = []
        self.tui_app.construct_results_scene(open_ports, fuzzing_results, web_analysis_results, aggressive_port_scan, subdomain_results, ftp_spider, found_vulnerabilities)
        self.tui_app.change_scene("results_scene")
    
    def identify_web_targets(self, open_ports: dict) -> dict:
        web_targets = {}
        for port, service in open_ports.items():
            if service in SSL_SERVICES or port in SSL_PORTS:
                web_targets[port] = f"https://{self.target}:{port}"
            elif service in PLAIN_HTTP_SERVICES or port in PLAIN_HTTP_PORTS:
                web_targets[port] = f"http://{self.target}:{port}"
        return web_targets

    def run_directory_fuzzer(self, web_targets: dict) -> list:
        fuzzing_results = []
        for port, url in web_targets.items():
            parsed_results = self.directory_fuzzer.start_fuzzing(url)
            fuzzing_results.extend(parsed_results)
            os.remove("ffuf_output.json")
        return fuzzing_results

    def run_web_analysis(self, web_targets: list) -> dict:
        if not web_targets:
            return {}
        analysis_results = {}
        for url in web_targets:
            result = self.web_analyzer.analyze(url)
            analysis_results[url] = result
        #print(analysis_results)
        return analysis_results

    def run_port_scanner_aggressive(self, ports: list[str]):
        scan_results = {}
        return PortScanner().parse_nmap_aggressive_xml(PortScanner().full_scan(self.target, ports=ports))

if __name__ == "__main__":
    app = Vanguard()
    app.run()

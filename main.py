import os
from modules.port_scanner import PortScanner
from modules.directory_fuzzer import DirectoryFuzzer
from modules.web_analyzer import WebAnalyzer
from core.config import PLAIN_HTTP_PORTS, PLAIN_HTTP_SERVICES, SSL_PORTS, SSL_SERVICES
from core.TUI import TUI


class Vanguard:
    """The main class for the Vanguard application, orchestrating all processes."""

    def __init__(self):
        self.port_scanner = PortScanner()
        self.directory_fuzzer = DirectoryFuzzer()
        self.web_analyzer = WebAnalyzer()
        self.tui_app = TUI(self)
        self.target = ""

    def run(self):
        self.tui_app.run()

    def set_target(self, target: str):
        self.target = target

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

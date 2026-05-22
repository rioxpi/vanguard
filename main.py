import os
from modules.port_scanner import PortScanner
from modules.directory_fuzzer import DirectoryFuzzer
from core.config import PLAIN_HTTP_PORTS, PLAIN_HTTP_SERVICES, SSL_PORTS, SSL_SERVICES
from core.TUI import TUI


class Vanguard:
    """The main class for the Vanguard application, orchestrating all processes."""

    def __init__(self):
        self.port_scanner = PortScanner()
        self.directory_fuzzer = DirectoryFuzzer()
        self.tui_app = TUI(self)

    def run(self):
        self.tui_app.run()

    def set_target(self, target: str):
        self.target = target
        self.tui_app.change_scene("scan_scene")
        open_ports = self.port_scanner.run_scan(target)
        web_targets = self.identify_web_targets(open_ports)
        fuzzing_results = self.run_directory_fuzzer(web_targets)
        self.tui_app.construct_results_scene(open_ports, fuzzing_results)

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


if __name__ == "__main__":
    app = Vanguard()
    app.run()

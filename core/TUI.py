from axto import Engine
from axto.scene import Scene
from axto.scene_manager import SceneManager
from axto.widgets.label import Label
from axto.widgets.input import Input
from axto.widgets.scroll_list import ScrollList
import threading

class TUI:
    """
    TUI class manages user interface.
    """

    def __init__(self, main_app) -> None:
        """Initializes the TUI with the main application reference.

        Args:
            main_app (Vanguard): Reference to the main Vanguard application to allow scene changes and data passing.
        """
        self.app = Engine()
        self.screen = None
        self.scene_manager = SceneManager(self.app)
        self.construct_main_menu()
        self.construct_scan_scene()
        self.scene_manager.switch_scene("main_menu")
        self.main_app = main_app

    def construct_main_menu(self) -> None:
        menu_scene = Scene()
        menu_scene.add_widget(Label(x=0.39, y=0.49, text="Enter target IP:"))
        input_widget = Input(x=0.49, y=0.49, width=20, placeholder="192.168.1.1")
        input_widget.bind("submit", lambda value: self.start_scan(value))
        menu_scene.add_widget(input_widget)
        self.scene_manager.add_scene("main_menu", menu_scene)

    def start_scan(self, target: str) -> None:
        self.main_app.set_target(target)
        self.change_scene("scan_scene")
        scan_thread = threading.Thread(
            target=self._scan_worker, 
            args=(target,),
            daemon=True
        )
        scan_thread.start()

    def _scan_worker(self, target: str) -> None:
        open_ports = self.main_app.port_scanner.quick_scan(target)
        
        if open_ports:
            web_targets = self.main_app.identify_web_targets(open_ports)
            aggressive_port_scan = self.main_app.run_port_scanner_aggressive(open_ports)
            fuzzing_results = self.main_app.run_directory_fuzzer(web_targets)
            web_analysis_results = self.main_app.run_web_analysis(fuzzing_results)
        else:
            open_ports = {"WARNING" : "Host has no open ports"}
            fuzzing_results = ["Nothing to show!"]
            web_analysis_results = {}
            aggressive_port_scan = {}
        self.construct_results_scene(open_ports, fuzzing_results, web_analysis_results, aggressive_port_scan)
        self.change_scene("results_scene")
        
    
    def construct_scan_scene(self) -> None:
        scan_scene = Scene()
        
        text = []
        
        text.append(" --   ---      /\\      |\\    |  |  |\\    |   ---")
        text.append("|    |        /  \\     | \\   |  |  | \\   |  |")
        text.append(" --  |       /----\\    |  \\  |  |  |  \\  |  |  - ")
        text.append("   | |      /      \\   |   \\ |  |  |   \\ |  |   | ")
        text.append(" --   ---  /        \\  |    \\|  |  |    \\|   ---  ")
        
        for i,v in enumerate(text):
            scan_scene.add_widget(Label(x=0.45, y=10+i, text=v, color="31"))
        self.scene_manager.add_scene("scan_scene", scan_scene)

    def construct_results_scene(
        self, open_ports: dict[str, str], fuzzing_output: list[str], web_analysis_output: dict[str, dict], nmap_aggressive_output: dict = {}
    ) -> None:
            
        results_scene = Scene()
        y_offset = 5
        
        # Open ports
        results_scene.add_widget(Label(x=0.49, y=y_offset, text="Open Ports:", color="32"))
        y_offset += 1
        for port, service in open_ports.items():
            results_scene.add_widget(Label(x=0.49, y=y_offset, text=f"{port}: {service}"))
            y_offset += 1
        
        # Fuzzing output
        y_offset += 1 
        results_scene.add_widget(Label(x=0.49, y=y_offset, text="Fuzzing Output:", color="32"))
        y_offset += 1
        for line in fuzzing_output:
            results_scene.add_widget(Label(x=0.49, y=y_offset, text=line))
            y_offset += 1
            
        # Web analysis output
        y_offset += 1
        #results_scene.add_widget(Label(x=0.49, y=y_offset, text="Web Analysis Output:", color="32"))
        y_offset += 1
        
        web_analysis_list = ScrollList(x=0.45, y=y_offset+1, width=1.0, height=0.5)
        
        items = []

        for url, analysis in web_analysis_output.items():
            items.append(f"url: {url}:")
            
            for tech, value in analysis['technologies'].items():
                items.append(f"  -> {tech}: {value}")
                
            for header in analysis['missing_headers']:
                items.append(f"  [!] Missing Header: {header}")
        
        # nmap aggressive
        if nmap_aggressive_output:
            items.append("")
            items.append("=== DETAILED REPORT ===")
            
            for ip, host_data in nmap_aggressive_output.items():
                mac_info = f" ({host_data['mac']})" if host_data['mac'] else ""
                hostname_info = f" [{', '.join(host_data['hostnames'])}]" if host_data['hostnames'] else ""
                items.append(f"Host: {ip}{mac_info}{hostname_info}")
                
                # OS
                if host_data.get("os_matches"):
                    items.append("  OS Detection:")
                    for os in host_data["os_matches"]:
                        items.append(f"    - {os['name']} (Accuracy: {os['accuracy']}%)")
                
                # NSE
                if host_data.get("ports"):
                    items.append("  Detailed Ports & Scripts:")
                    for port in host_data["ports"]:
                        items.append(f"    - {port['portid']}/{port['protocol']} -> {port['service']} | {port['version']}")
                        
                        if port.get("scripts"):
                            for script in port["scripts"]:
                                items.append(f"      [{script['script_name']}]")
                                for output_line in script['script_output'].split('\n'):
                                    if output_line.strip():
                                        items.append(f"        {output_line.strip()}")

        web_analysis_list.items = items
        results_scene.add_widget(web_analysis_list)
        
        self.scene_manager.add_scene("results_scene", results_scene)
        self.scene_manager.switch_scene("results_scene")


    def change_scene(self, scene_name: str) -> None:
        self.app.dispatch_to_main_thread(self.scene_manager.switch_scene, scene_name)
        #self.scene_manager.switch_scene(scene_name)

    def run(self) -> None:
        self.app.run()

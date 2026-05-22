from axto import Engine
from axto.scene import Scene
from axto.scene_manager import SceneManager
from axto.widgets.label import Label
from axto.widgets.input import Input
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
        menu_scene.add_widget(Label(x=10, y=5, text="Enter target IP:"))
        input_widget = Input(x=30, y=5, width=20, placeholder="192.168.1.1")
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
        open_ports = self.main_app.port_scanner.run_scan(target)
        web_targets = self.main_app.identify_web_targets(open_ports)
        fuzzing_results = self.main_app.run_directory_fuzzer(web_targets)
        self.construct_results_scene(open_ports, fuzzing_results)
        self.change_scene("results_scene")
        self.app._render_all_widgets() # TODO: Fix when library is updated to support dynamic updates without switching scenes
        
    
    def construct_scan_scene(self) -> None:
        scan_scene = Scene()
        scan_scene.add_widget(Label(x=10, y=5, text="Scanning ...", color="31"))
        self.scene_manager.add_scene("scan_scene", scan_scene)
        self.scene_manager.switch_scene("scan_scene")

    def construct_results_scene(
        self, open_ports: dict[str, str], fuzzing_output: list[str]
    ) -> None:
        results_scene = Scene()
        results_scene.add_widget(Label(x=10, y=5, text="Open Ports:", color="32"))
        y_offset = 7
        for port, service in open_ports.items():
            results_scene.add_widget(Label(x=12, y=y_offset, text=f"{port}: {service}"))
            y_offset += 1
        results_scene.add_widget(
            Label(x=10, y=y_offset + 1, text="Fuzzing Output:", color="32")
        )
        for line in fuzzing_output:
            results_scene.add_widget(Label(x=12, y=y_offset + 3, text=line))
            y_offset += 1
        self.scene_manager.add_scene("results_scene", results_scene)
        #self.scene_manager.switch_scene("results_scene")

    def change_scene(self, scene_name: str) -> None:
        self.scene_manager.switch_scene(scene_name)

    def run(self) -> None:
        self.app.run()

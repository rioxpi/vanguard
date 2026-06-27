from axto import Engine
from axto.scene import Scene
from axto.scene_manager import SceneManager
from axto.widgets import Label, Input, ScrollList, Button, CheckBox, Select, Container
from core.config import DIRECTORIES, ACTIVE_MODULES, NMAP_CONFIG
from pathlib import Path


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
        self.scan_type = "full"
        self.construct_settings_scene()
        self.construct_main_menu()
        self.construct_scan_scene()
        self.scene_manager.switch_scene("main_menu")
        self.main_app = main_app

    def construct_main_menu(self) -> None:
        menu_scene = Scene()
        menu_scene.add_widget(Label(x=0.39, y=0.49, text="Enter target IP:"))
        input_widget = Input(x=0.49, y=0.49, width=20, placeholder="192.168.1.1")
        input_widget.bind("submit", lambda value: self.construct_scan_type_scene(value))
        menu_scene.add_widget(input_widget)
        button = Button(x=0.5, y=0.6, text="SETTINGS")
        button.bind("press", lambda: self.scene_manager.switch_scene("settings_scene"))
        menu_scene.add_widget(button)
        self.scene_manager.add_scene("main_menu", menu_scene)

    def start_scan(self, target: str) -> None:
        self.main_app.set_target(target)
        self.scene_manager.switch_scene("scan_scene")

    def construct_settings_scene(self) -> None:
        settings_scene = Scene()
        nmap_options = [
            "T1 (sneaky)",
            "T2 (polite)",
            "T3 (normal)",
            "T4 (aggressive)",
            "T5 (insane)",
        ]

        container = Container(x=0.4, y=0.4, width=50, height=50, has_border=False)

        nmap_aggressive_option = container.add_child(
            Select(x=0, y=2, width=50, options=nmap_options, default_index=3)
        )
        enable_fuzzing = container.add_child(
            CheckBox(x=0, y=4, label="Enable Fuzzing", checked=ACTIVE_MODULES["ffuf"])
        )
        enable_nmap_aggressive_scan = container.add_child(
            CheckBox(
                x=0,
                y=6,
                label="Enable Nmap aggressive scanning",
                checked=ACTIVE_MODULES["nmap_aggressive"],
            )
        )
        nmap_port_flag = container.add_child(
            Input(x=0, y=8, width=30, placeholder="Nmap port flag (default: -F)")
        )
        custom_wordlist = container.add_child(
            Input(x=0, y=10, width=25, placeholder="Custom wordlist")
        )

        custom_wordlist.bind(
            "submit",
            lambda key: (
                DIRECTORIES.__setitem__("wordlist", key)
                if Path(key).exists()
                else custom_wordlist.trigger_error_flash()
            ),
        )
        enable_fuzzing.bind(
            "change", lambda state: ACTIVE_MODULES.__setitem__("ffuf", state)
        )
        enable_nmap_aggressive_scan.bind(
            "change", lambda state: ACTIVE_MODULES.__setitem__("nmap_aggressive", state)
        )
        nmap_aggressive_option.bind(
            "change",
            lambda val, idx: NMAP_CONFIG.__setitem__(
                "aggressive_level", f"-{val[0]}{val[1]}"
            ),
        )
        nmap_port_flag.bind(
            "submit", lambda key: NMAP_CONFIG.__setitem__("port_flag", f"{key}")
        )

        settings_scene.add_widget(container)

        back_button = Button(x=0.5, y=0.9, text="BACK")
        back_button.bind("press", lambda: self.scene_manager.switch_scene("main_menu"))
        settings_scene.add_widget(back_button)
        self.scene_manager.add_scene("settings_scene", settings_scene)

    def construct_scan_scene(self) -> None:
        scan_scene = Scene()

        text = []

        text.append(" --   ---      /\\      |\\    | |\\    |  |  |\\    |   --- ")
        text.append("|    |        /  \\     | \\   | | \\   |  |  | \\   |  |    ")
        text.append(" --  |       /----\\    |  \\  | |  \\  |  |  |  \\  |  |  - ")
        text.append("   | |      /      \\   |   \\ | |   \\ |  |  |   \\ |  |   |")
        text.append(" --   ---  /        \\  |    \\| |    \\|  |  |    \\|   --- ")

        container = Container(x=0.4, y=0.4, width=63, height=5, has_border=False)

        for i, v in enumerate(text):
            container.add_child(Label(x=0, y=i + 1, text=v, color="31"))

        scan_scene.add_widget(container)
        self.scene_manager.add_scene("scan_scene", scan_scene)

    def construct_scan_type_scene(self, target: str) -> None:
        def _set_fast_scan():
            ACTIVE_MODULES["nmap_aggressive"] = False
            ACTIVE_MODULES["subdomain"] = False
            ACTIVE_MODULES["web_analyzer"] = False
            self.scan_type = "fast"
            self.start_scan(target)

        scene = Scene()
        cnt = Container(x=0.45, y=0.45, width=50, height=1, has_border=False)

        fast_scan = cnt.add_child(Button(0, 0, "FAST SCAN"))
        full_scan = cnt.add_child(Button(15, 0, "FULL SCAN"))

        fast_scan.bind("press", lambda: _set_fast_scan())
        full_scan.bind("press", lambda: self.start_scan(target))

        scene.add_widget(cnt)
        self.scene_manager.add_scene(name="type-choice", scene=scene)
        self.scene_manager.switch_scene("type-choice")

    def construct_results_scene(
        self,
        open_ports: dict[str, str],
        fuzzing_output: list[str],
        web_analysis_output: dict[str, dict],
        nmap_aggressive_output: dict = {},
        subdomain_results: dict = {},
        ftp_spider: list = [],
        vulnerabilities: list = [],
    ) -> None:

        results_scene = Scene()

        results_scene.add_widget(
            Label(x=0.03, y=0.03, text="[ SCAN RESULTS SUITE ]", color="32")
        )

        # left column
        fuzzing_output_scroll_list = ScrollList(0.03, 0.10, 0.45, 0.75)
        left_column_items = []

        # open ports
        left_column_items.append("┌────────────────────────────────────────┐")
        left_column_items.append("│                OPEN PORTS              │")
        left_column_items.append("└────────────────────────────────────────┘")
        if open_ports:
            for port, service in open_ports.items():
                left_column_items.append(f"  • Port {port:<5} ➔  {service}")
        else:
            left_column_items.append("  [!] does not detect open ports")

        left_column_items.append("")

        # Fuzzing
        left_column_items.append("┌────────────────────────────────────────┐")
        left_column_items.append("│              FUZZING OUTPUT            │")
        left_column_items.append("└────────────────────────────────────────┘")
        if fuzzing_output:
            for line in fuzzing_output:
                left_column_items.append(f"  {line}")
        else:
            left_column_items.append("  [!] No results")

        fuzzing_output_scroll_list.items = left_column_items
        results_scene.add_widget(fuzzing_output_scroll_list)

        web_analysis_list = ScrollList(0.51, 0.10, 0.46, 0.75)
        right_column_items = []

        # Web Analyzer
        right_column_items.append("┌────────────────────────────────────────┐")
        right_column_items.append("│               WEB ANALYZER             │")
        right_column_items.append("└────────────────────────────────────────┘")

        if ACTIVE_MODULES.get("web_analyzer"):
            if web_analysis_output:
                for url, analysis in web_analysis_output.items():
                    right_column_items.append(f" Target: {url}")

                    if analysis.get("technologies"):
                        right_column_items.append("  Detected technologies:")
                        for tech, value in analysis["technologies"].items():
                            right_column_items.append(f"    ├─ {tech}: {value}")

                    if analysis.get("missing_headers"):
                        right_column_items.append("  missing security headers:")
                        for header in analysis["missing_headers"]:
                            right_column_items.append(f"    └─ [!] {header}")
            else:
                right_column_items.append("  No data.")
        else:
            right_column_items.append("  This module is disabled")

        # Nmap Aggressive
        nmap_parsed = []
        right_column_items.append("")
        right_column_items.append("┌────────────────────────────────────────┐")
        right_column_items.append("│             DETAILED REPORT            │")
        right_column_items.append("└────────────────────────────────────────┘")

        if nmap_aggressive_output and ACTIVE_MODULES.get("nmap_aggressive"):
            for ip, host_data in nmap_aggressive_output.items():
                mac_info = f" ({host_data['mac']})" if host_data.get("mac") else ""
                hostname_info = (
                    f" [{', '.join(host_data['hostnames'])}]"
                    if host_data.get("hostnames")
                    else ""
                )
                nmap_parsed.append(f" Host: {ip}{mac_info}{hostname_info}")

                # OS
                if host_data.get("os_matches"):
                    nmap_parsed.append("   OS Detection:")
                    for os in host_data["os_matches"]:
                        nmap_parsed.append(
                            f"    └─ {os['name']} (Accuracy: {os['accuracy']}%)"
                        )

                # Ports & NSE
                if host_data.get("ports"):
                    nmap_parsed.append("   Detailed ports & scripts:")
                    for port in host_data["ports"]:
                        nmap_parsed.append(
                            f"    ├─ {port['portid']}/{port['protocol']} ➔ {port['service']} | {port['version']}"
                        )

                        if port.get("scripts"):
                            for script in port["scripts"]:
                                nmap_parsed.append(
                                    f"    │  └─ [{script['script_name']}]"
                                )
                                for output_line in script["script_output"].split("\n"):
                                    if output_line.strip():
                                        nmap_parsed.append(
                                            f"    │     {output_line.strip()}"
                                        )

            right_column_items.extend(nmap_parsed)

        elif not ACTIVE_MODULES.get("nmap_aggressive"):
            nmap_parsed = "THIS MODULE IS DISABLED"
            right_column_items.append("  This module is disabled")
        else:
            right_column_items.append("  No detailed report")

        # Subdomains
        right_column_items.append("")
        right_column_items.append("┌────────────────────────────────────────┐")
        right_column_items.append("│             SUBDOMAIN RESULTS          │")
        right_column_items.append("└────────────────────────────────────────┘")
        if ACTIVE_MODULES.get("subdomain"):
            if subdomain_results:
                for subdomain, ip in subdomain_results.items():
                    right_column_items.append(f"   {subdomain} ➔ {ip}")
            else:
                right_column_items.append("  No subdomains found")
        else:
            right_column_items.append("   This module is disabled")

        # VULNERABILITIES
        right_column_items.append("")
        right_column_items.append("┌────────────────────────────────────────┐")
        right_column_items.append("│             VULNERABILITIES            │")
        right_column_items.append("└────────────────────────────────────────┘")

        if vulnerabilities:
            for d in vulnerabilities:
                right_column_items.append(f" {d['title']}")
                right_column_items.append(f"  ├─ type: {d['type']}")
                right_column_items.append(f"  ├─ exploit id: {d['exploit_id']}")
                right_column_items.append(f"  └─ path: {d['path']}")
        else:
            right_column_items.append("No vulnerabilities found")

        # FTP
        right_column_items.append("")
        right_column_items.append("┌────────────────────────────────────────┐")
        right_column_items.append("│                FTP FILES               │")
        right_column_items.append("└────────────────────────────────────────┘")
        if ftp_spider:
            for i in ftp_spider:
                right_column_items.append(f"  └─ {i}")
        else:
            right_column_items.append("  No files found on FTP")

        web_analysis_list.items = right_column_items
        results_scene.add_widget(web_analysis_list)

        buttons_container = Container(0.4, 0.89, 50, 1, False)

        save_to_md_button = buttons_container.add_child(
            Button(0, 0, "SAVE REPORT (MARKDOWN)")
        )
        save_to_md_button.bind(
            "press",
            lambda: self.main_app.data_saver.save_to_markdown(
                self.main_app.target,
                open_ports,
                fuzzing_output,
                subdomain_results,
                web_analysis_output,
                ftp_spider,
                nmap_parsed,
                self.scan_type,
                vulnerabilities,
            ),
        )

        advanced_button = buttons_container.add_child(Button(26, 0, "ADVANCED"))
        advanced_button.bind(
            "press",
            lambda: self.construct_advanced_scene(
                open_ports,
                fuzzing_output,
                subdomain_results,
                web_analysis_output,
                ftp_spider,
                nmap_parsed,
                vulnerabilities,
            ),
        )

        results_scene.add_widget(buttons_container)

        self.scene_manager.add_scene("results_scene", results_scene)
        self.scene_manager.switch_scene("results_scene")

    def construct_advanced_scene(
        self,
        open_ports,
        fuzzing_output,
        subdomain_results,
        web_analysis_output,
        ftp_spider,
        nmap_parsed,
        vulnerabilities,
    ):
        advanced_scene = Scene()

        save_to_json_button = Button(0.45, 0.5, "SAVE TO JSON")

        save_to_json_button.bind(
            "press",
            lambda: self.main_app.data_saver.save_to_json(
                self.main_app.target,
                open_ports,
                fuzzing_output,
                subdomain_results,
                web_analysis_output,
                ftp_spider,
                nmap_parsed,
                self.scan_type,
                vulnerabilities,
            ),
        )

        advanced_scene.add_widget(save_to_json_button)

        self.scene_manager.add_scene("advanced", advanced_scene)
        self.scene_manager.switch_scene("advanced")

    def change_scene(self, scene_name: str) -> None:
        self.app.dispatch_to_main_thread(self.scene_manager.switch_scene, scene_name)

    def run(self) -> None:
        self.app.run()

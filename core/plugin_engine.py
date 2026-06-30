import os
import importlib.util
import sys

class PluginEngine:
    def __init__(self, plugin_dir: str = "plugins") -> None:
        self.plugin_dir = plugin_dir
        self.loaded_plugins = []
    
    def load_plugins(self):
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir)
            return

        for filename in os.listdir(self.plugin_dir):
            if filename.endswith(".py") and not filename.startswith("__"):
                plugin_name = filename[:-3]
                filepath = os.path.join(self.plugin_dir, filename)
                
                try:
                    spec = importlib.util.spec_from_file_location(plugin_name, filepath)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[plugin_name] = module
                    spec.loader.exec_module(module)
                    
                    if hasattr(module, "METADATA") and hasattr(module, "can_handle") and hasattr(module, "run"):
                        self.loaded_plugins.append(module)
                except Exception as e:
                    raise InterruptedError(f"ERROR during loading module: {e}")
                
    
    def execute_plugins(self, target, recon_data):
        plugin_results = {}
        
        for plugin in self.loaded_plugins:
            try:
                if plugin.can_handle(recon_data):
                    p_name = plugin.METADATA['name']
                    
                    result = plugin.run(target, recon_data)
                    if result:
                        plugin_results[p_name] = result
            except Exception as e:
                plugin_results[plugin.METADATA['name']] = f"ERROR during code execution: {e}"
        
        return plugin_results
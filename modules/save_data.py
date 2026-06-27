import time
import os
import json

class DataSaver():
    def __init__(self) -> None:
        pass
    
    def save_to_markdown(self, target : str,open_ports : list, fuzzing : list, subdomains : list = [], web_analyzer : dict[str, dict] = {},ftp_data : list = [], formatted_nmap_aggressive : list = [],scan_type : str = "Unknown", vulnerabilities : list = []) -> None:
        os.makedirs("reports", exist_ok=True)
        
        time_file = time.strftime("%Y-%m-%d_%H-%M")
        time_header = time.strftime("%Y-%m-%d %H:%M:%S")
        
        filename = f"report_{time_file}.md"
        path = os.path.join("reports", filename)
        
        with open(path, "w", encoding='utf-8') as file:
            # HEADER
            file.write(f"# REPORT: {time_header}\n\n")
            
            # INFORMATION 
            file.write("## GENERAL INFORMATION\n\n")
            file.write(f" * Date: **{time_header}**\n")
            file.write(f" * Target: **{target}**\n")
            file.write(f" * Scan type: **{scan_type}**\n\n")      
            
            # OPEN PORTS
            file.write("## OPEN PORTS\n\n")
            for p in open_ports:
                file.write(f" * {p}\n")
            
            file.write("\n")
            
            # WEB
            
            # fuzzing data
            if fuzzing:
                file.write("## FUZZING RESULTS\n\n")
                for f in fuzzing:
                    file.write(f" * {f}\n")
                
                file.write("\n")
            
            # subdomains
            if subdomains:
                file.write("## SUBDOMAINS\n\n")
                for s in subdomains:
                    file.write(f" * {s}\n")

                file.write("\n")
                
            # web analyzer
            if web_analyzer:
                file.write("## WEB ANALYZER\n\n")
                                
                for url, analysis in web_analyzer.items():
                    file.write(f" * url: {url}\n")
                    
                    for tech, value in analysis['technologies'].items():
                        file.write(f"   - {tech}: {value}\n")
                        
                    for header in analysis['missing_headers']:
                        file.write(f"   - [!] Missing Header: {header}\n")        

                file.write("\n")
                
            # FTP
            if ftp_data:
                file.write("## FTP\n\n")
                file.write("```markdown\n")
                for f in ftp_data:
                    file.write(f"{f}\n")
                file.write('```\n')
                
                file.write("\n")
            
            # VULNERABILITIES
            if vulnerabilities:
                file.write("## VULNERABILITIES\n\n")
                for idx, data in enumerate(vulnerabilities):
                    file.write(f" {idx+1}. {data["title"]}\n")
                    file.write(f"   - type: {data['type']}\n")
                    file.write(f"   - exploit id: {data['exploit_id']}\n")
                    file.write(f"   - path: {data['path']}\n") 
                
                file.write("\n")
                
            # NMAP AGGRESSIVE
            if formatted_nmap_aggressive:
                file.write("## NMAP AGGRESSIVE\n\n")
                file.write("```markdown\n")
                for f in formatted_nmap_aggressive:
                    file.write(f"{f}\n")

                file.write("```\n")
                
                file.write("\n")    
    
    def save_to_json(self, target : str,open_ports : list, fuzzing : list, subdomains : list = [], web_analyzer : dict[str, dict] = {},ftp_data : list = [], formatted_nmap_aggressive : list = [],scan_type : str = "Unknown", vulnerabilities : list = []) -> None:
        os.makedirs("reports", exist_ok=True)
        
        time_file = time.strftime("%Y-%m-%d_%H-%M")
        time_header = time.strftime("%Y-%m-%d %H:%M:%S")
        
        filename = f"report_{time_file}.json"
        path = os.path.join("reports", filename)
        
        data = {
            'information' : {'date' : time_header, 'target' : target, 'scan_type' : scan_type},
            'open_ports' : open_ports,
            'fuzzing' : [],
            'subdomains' : [],
            'web_analyzer' : {},
            'ftp' : [],
            'nmap_aggressive' : [],
            'vulnerabilities' : []
        }
        
        if fuzzing:
            data['fuzzing'] = fuzzing
        else:
            data['fuzzing'] = ["NO DATA"]
        
        if subdomains:
            data['subdomains'] = subdomains
        else:
            data['subdomains'] = ["NO DATA"]
        
        if web_analyzer:
            data['web_analyzer'] = web_analyzer
        else:
            data['web_analyzer']  = {'info' : 'NO DATA'}
        
        if ftp_data:
            data['ftp'] = ftp_data
        else:
            data['ftp'] = ['NO DATA']
        
        if formatted_nmap_aggressive:
            data['nmap_aggressive'] = formatted_nmap_aggressive
        else:
            data['nmap_aggressive'] = ['NO DATA']
        
        if vulnerabilities:
            data['vulnerabilities'] = vulnerabilities
        else:
            data['vulnerabilities'] = ['NO DATA']
        
        with open(path, "w", encoding='utf-8') as file:
            json.dump(data, file, indent=4, ensure_ascii=False)
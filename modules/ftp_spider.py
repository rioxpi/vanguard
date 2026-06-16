from ftplib import FTP 

class FtpSpider:
    def check_anonymous_login(self, target):
        try:
            ftp = FTP()
            ftp.connect(target, timeout=5)
            ftp.login()
            ftp.quit()
            return True
        except:
            return False

    def search_files(self, ftp : FTP, path=".", prefix="") -> list:
        out = []
        
        try:
            ftp.cwd(path)
            
            items = ftp.nlst()
            
            items = [item for item in items if item not in ['.', '..']]
            
            
        except Exception as e:
            return []

        try:
            for index, item in enumerate(items):
                is_last = (index == (len(items) - 1))
                connector = "└── " if is_last else "├── "
                
                out.append(f"{prefix}{connector}{item}")
                
                try:
                    new_prefix = f"{prefix}{"  " if is_last else "│  "}"
                    current_dir = ftp.pwd()
                    out.extend(self.search_files(ftp, item, new_prefix))
                    
                    ftp.cwd(current_dir)
                except:
                    pass
                
            
        except Exception as e:
            print(f"ERROR: {e}")

        return out
        
    def scan(self, target: str):
        if not self.check_anonymous_login(target):
            return ["Cannot connect using anonymous accounts"]
            
        try:
            ftp = FTP(target)
            ftp.login()
            
            data = self.search_files(ftp, "/")
                        
            ftp.quit()
            return data
        except:
            return ["ERROR"]


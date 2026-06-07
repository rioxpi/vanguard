import requests
from urllib3.exceptions import InsecureRequestWarning
from core.config import SECURITY_HEADERS

class WebAnalyzer:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False  # Disable SSL verification
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning) # type: ignore
        self.results = {}

    def analyze(self, url):
        results = {
            'technologies': {},
            'missing_headers': []
        }   
        
        try:
            response = self.session.get(url, verify=False, timeout=10, allow_redirects=True)
            headers = response.headers
            
            if 'Server' in headers:
                results['technologies']['Server'] = headers['Server']
            
            if 'X-Powered-By' in headers:
                results['technologies']['X-Powered-By'] = headers['X-Powered-By']
                
            for header in SECURITY_HEADERS:
                if header not in headers:
                    results['missing_headers'].append(header)
            
            return results
        except requests.exceptions.ReadTimeout:
            results['status'] = 'timeout'
            results['error'] = 'Host did not respond within the specified time (10s).'
            return results

        except requests.exceptions.ConnectionError:
            results['status'] = 'connection_error'
            results['error'] = 'Cannot connect to the host.'
            return results
        except requests.RequestException as e:
            raise Exception(f"Error analyzing {url}: {str(e)}")
SSL_SERVICES = {"https", "ssl/http", "https-alt", "ssl/https"}
PLAIN_HTTP_SERVICES = {
    "http",
    "http-alt",
    "jetty",
    "apache-tomcat",
    "nginx",
    "lighttpd",
    "http-proxy",
}
SSL_PORTS = {"443", "8443", "9443"}
PLAIN_HTTP_PORTS = {
    "80",
    "3000",
    "5000",
    "8000",
    "8080",
    "8081",
    "8088",
    "8888",
    "9000",
}

DIRECTORIES = {
    "ffuf": "programs/ffuf/ffuf",
    "nmap": "programs/nmap/run-nmap.sh",
    "wordlist": "programs/wordlist.txt",
    "nmap_bin": "programs/nmap/nmap",
    "subfinder": "programs/subfinder/subfinder"
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security"
]

SHA_256_HASHES = {
    "ffuf": "b0183aeed13d3ccea5db79809ca4135b7561257406a0f5d6f982e0551abea4e7",
    "nmap": "4e982d8c285bb7d352628b80ae1216f3ba63e51a10ea64c0cfbbe3ae917d362b",
    "nmap_bin": "d25bf2109478fc71ea7efb3c5a834d9301f03788eeda47da49118e2170434d83",
    "subfinder": "88e6b07d47afee46804db926f46bba99eadee74e0ccb32b2f792bfea62b9da0c",
    "wordlist": "a85795c71df1269772054dfc13edda2fc80edaf24d59abcd98c8a62dd76d4820"
}

ACTIVE_MODULES = {
    "nmap_base" : True,
    "nmap_aggressive" : True,
    "ffuf" : True,
    "subdomain" : True,
    "web_analyzer" : True
}
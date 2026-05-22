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
}

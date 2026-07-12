"""Domain intelligence engine."""

import dns.resolver
import requests
import socket
import ssl
from typing import Dict, Any, List, Optional
from datetime import datetime


class DomainOSINT:
    """
    Main engine for domain intelligence gathering.
    
    Combines DNS, WHOIS, SSL, and technology detection.
    """
    
    def __init__(self):
        """Initialize the domain OSINT engine."""
        self.session = requests.Session()
    
    def analyze(self, domain: str) -> Dict[str, Any]:
        """
        Perform complete domain analysis.
        
        Args:
            domain: Target domain.
            
        Returns:
            Comprehensive analysis results.
        """
        result = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'dns': self.get_dns_records(domain),
            'ssl': self.get_ssl_info(domain),
            'whois': self.get_whois_basic(domain),
            'technologies': self.detect_technologies(domain),
        }
        
        return result
    
    def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get all DNS records for a domain."""
        records = {}
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        
        return records
    
    def get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'san': [x[1] for x in cert.get('subjectAltName', [])],
                    }
        except Exception as e:
            return {'error': str(e)}
    
    def get_whois_basic(self, domain: str) -> Dict[str, Any]:
        """Get basic WHOIS information."""
        try:
            import socket
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(('whois.verisign-grs.com', 43))
            sock.send(f'{domain}\r\n'.encode())
            
            response = b''
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response += data
            
            sock.close()
            
            return {'raw': response.decode('utf-8', errors='ignore')}
        except Exception as e:
            return {'error': str(e)}
    
    def detect_technologies(self, domain: str) -> List[str]:
        """Detect technologies used by a website."""
        technologies = []
        
        try:
            response = self.session.get(
                f'https://{domain}',
                timeout=10,
                allow_redirects=True
            )
            
            headers = response.headers
            content = response.text.lower()
            
            # Server header
            if 'server' in headers:
                technologies.append(f"Server: {headers['server']}")
            
            # Check for common frameworks
            if 'x-powered-by' in headers:
                technologies.append(f"Powered by: {headers['x-powered-by']}")
            
            # Content-based detection
            if 'wp-content' in content:
                technologies.append('WordPress')
            elif 'drupal' in content:
                technologies.append('Drupal')
            elif 'joomla' in content:
                technologies.append('Joomla')
            
            if 'react' in content or 'reactjs' in content:
                technologies.append('React')
            elif 'angular' in content:
                technologies.append('Angular')
            elif 'vue' in content:
                technologies.append('Vue.js')
            
            if 'bootstrap' in content:
                technologies.append('Bootstrap')
            if 'jquery' in content:
                technologies.append('jQuery')
        
        except Exception:
            pass
        
        return technologies
    
    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using common prefixes."""
        common_subdomains = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'ns1', 'ns2',
            'dns', 'webmail', 'cpanel', 'admin', 'api', 'dev',
            'staging', 'test', 'blog', 'shop', 'store', 'app',
        ]
        
        found = []
        
        for sub in common_subdomains:
            subdomain = f"{sub}.{domain}"
            try:
                socket.gethostbyname(subdomain)
                found.append(subdomain)
            except socket.gaierror:
                pass
        
        return found

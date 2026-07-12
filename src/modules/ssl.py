"""SSL certificate analysis module."""

import ssl
import socket
from typing import Dict, Any


class SSLModule:
    """SSL certificate analysis."""
    
    def analyze(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL certificate for a domain."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'not_after': cert.get('notAfter'),
                    }
        except Exception as e:
            return {'error': str(e)}

"""DNS analysis module."""

import dns.resolver
from typing import Dict, List


class DNSModule:
    """DNS record analysis."""
    
    def query(self, domain: str, record_type: str = 'A') -> List[str]:
        """Query DNS records."""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            return [str(r) for r in answers]
        except Exception:
            return []
    
    def get_all_records(self, domain: str) -> Dict[str, List[str]]:
        """Get all DNS record types."""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'SRV']
        return {rt: self.query(domain, rt) for rt in record_types}

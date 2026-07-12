"""HTML report generator."""

import json
from typing import Dict, Any
from pathlib import Path
from datetime import datetime


class ReportGenerator:
    """Generate HTML reports from analysis data."""
    
    def generate(self, data: Dict[str, Any], output_path: str) -> str:
        """Generate an HTML report."""
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Domain Analysis: {data.get('domain', 'Unknown')}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; }}
        .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; }}
        .section h2 {{ color: #666; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 8px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f5f5f5; }}
    </style>
</head>
<body>
    <h1>Domain Analysis: {data.get('domain', 'Unknown')}</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="section">
        <h2>DNS Records</h2>
        <pre>{json.dumps(data.get('dns', {}), indent=2)}</pre>
    </div>
    
    <div class="section">
        <h2>SSL Certificate</h2>
        <pre>{json.dumps(data.get('ssl', {}), indent=2)}</pre>
    </div>
    
    <div class="section">
        <h2>Technologies</h2>
        <ul>
            {''.join(f'<li>{t}</li>' for t in data.get('technologies', []))}
        </ul>
    </div>
</body>
</html>
"""
        
        path = Path(output_path)
        path.write_text(html)
        return str(path)

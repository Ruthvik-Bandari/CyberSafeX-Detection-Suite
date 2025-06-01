import os
import uuid
import logging
import hashlib
# import magic  # Removed temporarily
import json
import mimetypes
import platform
import re
import sqlite3
from datetime import datetime
from PIL import Image, ExifTags
import plotly.graph_objects as go
import pandas as pd
import numpy as np

class ForensicTool:
    def __init__(self):
        """Initialize the forensic tool"""
        self.cases = {}
        self.version = "1.0.0"
        logging.info(f"Digital Forensics Tool v{self.version} initialized")

    def create_case(self, case_name, case_description="", investigator=""):
        """Create a new case"""
        case_id = str(uuid.uuid4())
        self.cases[case_id] = {
            'name': case_name,
            'description': case_description,
            'investigator': investigator,
            'created_at': datetime.now(),
            'evidence': []
        }
        logging.info(f"Created new case: {case_name} (ID: {case_id})")
        return case_id

    def add_evidence(self, case_id, evidence_path, evidence_type="file", description=""):
        """Add evidence to a case"""
        if case_id not in self.cases:
            raise ValueError("Case not found")

        evidence_id = str(uuid.uuid4())
        evidence = {
            'id': evidence_id,
            'path': evidence_path,
            'type': evidence_type,
            'description': description,
            'added_at': datetime.now()
        }
        self.cases[case_id]['evidence'].append(evidence)
        logging.info(f"Added evidence to case {case_id}: {evidence_path}")
        return evidence_id

    def analyze_file(self, file_path):
        """Perform comprehensive file analysis"""
        results = {}
        
        # Read file content for analysis
        with open(file_path, 'rb') as f:
            content = f.read()
            results['content_analysis'] = self._analyze_content(content)
        
        # Basic file information
        results['file_info'] = {
            'name': os.path.basename(file_path),
            'size': os.path.getsize(file_path),
            'created': datetime.fromtimestamp(os.path.getctime(file_path)),
            'modified': datetime.fromtimestamp(os.path.getmtime(file_path)),
            'accessed': datetime.fromtimestamp(os.path.getatime(file_path))
        }
        
        # File type identification
        results['file_type'] = {
            'mime_type': mimetypes.guess_type(file_path)[0] or 'application/octet-stream',
            'extension': os.path.splitext(file_path)[1]
        }
        
        # Hash values
        results['hashes'] = self._calculate_hashes(file_path)
        
        # Metadata extraction
        results['metadata'] = self._extract_metadata(file_path)
        
        # Security analysis
        results['security'] = self._analyze_security(file_path)
        
        return results

    def _calculate_hashes(self, file_path):
        """Calculate various hash values for a file"""
        hashes = {}
        algorithms = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256(),
            'sha512': hashlib.sha512()
        }
        
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                for hash_obj in algorithms.values():
                    hash_obj.update(chunk)
        
        for name, hash_obj in algorithms.items():
            hashes[name] = hash_obj.hexdigest()
        
        return hashes

    def _extract_metadata(self, file_path):
        """Extract metadata from various file types"""
        metadata = {}
        file_type = mimetypes.guess_type(file_path)[0] or 'application/octet-stream'
        
        if file_type.startswith('image/'):
            try:
                with Image.open(file_path) as img:
                    metadata['image'] = {
                        'format': img.format,
                        'mode': img.mode,
                        'size': img.size,
                        'exif': {}
                    }
                    
                    if 'exif' in img.info:
                        for tag_id in ExifTags.TAGS:
                            try:
                                tag = ExifTags.TAGS[tag_id]
                                value = img._getexif().get(tag_id)
                                if value:
                                    metadata['image']['exif'][tag] = str(value)
                            except:
                                continue
            except Exception as e:
                logging.error(f"Error extracting image metadata: {e}")
        
        return metadata

    def _analyze_security(self, file_path):
        """Perform security analysis on a file"""
        security_results = {
            'suspicious_patterns': [],
            'risk_level': 'low',
            'warnings': []
        }
        
        # File entropy analysis
        entropy = self._calculate_entropy(file_path)
        security_results['entropy'] = entropy
        
        if entropy > 7.5:
            security_results['warnings'].append('High entropy detected - possible encryption/compression')
            security_results['risk_level'] = 'medium'
        
        # Check for suspicious patterns
        patterns = {
            'possible_shellcode': rb'\x90{10,}',  # NOP sled
            'possible_exploit': rb'(\x00){100,}',  # Long null byte sequence
            'possible_script': rb'<script[^>]*>.*?</script>',  # JavaScript
        }
        
        with open(file_path, 'rb') as f:
            content = f.read()
            for pattern_name, pattern in patterns.items():
                if re.search(pattern, content):
                    security_results['suspicious_patterns'].append(pattern_name)
                    security_results['risk_level'] = 'high'
        
        return security_results

    def _calculate_entropy(self, file_path):
        """Calculate Shannon entropy of a file"""
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(x) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy

    def process_evidence(self, case_id, evidence_id, num_workers=4):
        """Process evidence with comprehensive analysis"""
        if case_id not in self.cases:
            raise ValueError("Case not found")

        evidence = None
        for e in self.cases[case_id]['evidence']:
            if e['id'] == evidence_id:
                evidence = e
                break

        if not evidence:
            raise ValueError("Evidence not found")

        # Create output directory
        case_dir = os.path.join('cases', case_id)
        output_dir = os.path.join(case_dir, 'results')
        os.makedirs(output_dir, exist_ok=True)

        # Perform analysis
        analysis_results = self.analyze_file(evidence['path'])

        # Generate visualizations
        visualizations = self._create_visualizations(analysis_results)
        
        # Convert visualizations to HTML
        vis_html = {
            'timeline': visualizations['timeline'].to_html(full_html=False),
            'byte_freq': visualizations['byte_freq'].to_html(full_html=False),
            'entropy_map': visualizations['entropy_map'].to_html(full_html=False),
            'composition': visualizations['composition'].to_html(full_html=False)
        }

        # Create detailed report
        report_path = os.path.join(output_dir, f"{evidence_id}_report.html")
        with open(report_path, 'w') as f:
            f.write(f"""
            <html>
                <head>
                    <title>Forensic Analysis Report</title>
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
                    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
                </head>
                <body class="container mt-4">
                    <h1>Forensic Analysis Report</h1>
                    <hr>
                    <h2>Case Information</h2>
                    <div class="card mb-4">
                        <div class="card-body">
                            <p><strong>Case Name:</strong> {self.cases[case_id]['name']}</p>
                            <p><strong>Investigator:</strong> {self.cases[case_id]['investigator']}</p>
                            <p><strong>Evidence File:</strong> {os.path.basename(evidence['path'])}</p>
                            <p><strong>Analysis Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                        </div>
                    </div>

                    <h2>File Information</h2>
                    <div class="card mb-4">
                        <div class="card-body">
                            <p><strong>Name:</strong> {analysis_results['file_info']['name']}</p>
                            <p><strong>Size:</strong> {self._format_size(analysis_results['file_info']['size'])}</p>
                            <p><strong>Type:</strong> {analysis_results['file_type']['mime_type']}</p>
                            <p><strong>Created:</strong> {analysis_results['file_info']['created']}</p>
                            <p><strong>Modified:</strong> {analysis_results['file_info']['modified']}</p>
                        </div>
                    </div>

                    <h2>Hash Values</h2>
                    <div class="card mb-4">
                        <div class="card-body">
                            <p><strong>MD5:</strong> {analysis_results['hashes']['md5']}</p>
                            <p><strong>SHA1:</strong> {analysis_results['hashes']['sha1']}</p>
                            <p><strong>SHA256:</strong> {analysis_results['hashes']['sha256']}</p>
                        </div>
                    </div>

                    <h2>Security Analysis</h2>
                    <div class="card mb-4">
                        <div class="card-body">
                            <p><strong>Risk Level:</strong> <span class="badge bg-{self._get_risk_color(analysis_results['security']['risk_level'])}">{analysis_results['security']['risk_level'].upper()}</span></p>
                            <p><strong>Entropy:</strong> {analysis_results['security']['entropy']:.2f}</p>
                            {self._format_warnings(analysis_results['security']['warnings'])}
                            {self._format_patterns(analysis_results['security']['suspicious_patterns'])}
                        </div>
                    </div>

                    <h2>Timeline Analysis</h2>
                    <div class="card mb-4">
                        <div class="card-body">
                            {vis_html['timeline']}
                        </div>
                    </div>

                    <h2>Content Analysis</h2>
                    <div class="row">
                        <div class="col-md-6">
                            <div class="card mb-4">
                                <div class="card-header">
                                    <h5 class="mb-0">Byte Frequency Distribution</h5>
                                </div>
                                <div class="card-body">
                                    {vis_html['byte_freq']}
                                </div>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="card mb-4">
                                <div class="card-header">
                                    <h5 class="mb-0">File Composition</h5>
                                </div>
                                <div class="card-body">
                                    {vis_html['composition']}
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="card mb-4">
                        <div class="card-header">
                            <h5 class="mb-0">Entropy Analysis</h5>
                        </div>
                        <div class="card-body">
                            <p class="text-muted">This graph shows the entropy distribution across the file. Higher values indicate more random or encrypted data.</p>
                            {vis_html['entropy_map']}
                        </div>
                    </div>

                    {self._format_metadata_section(analysis_results['metadata'])}
                </body>
            </html>
            """)

        return {
            'status': 'completed',
            'output_directory': output_dir,
            'report_path': report_path,
            'results': analysis_results
        }

        return {
            'status': 'completed',
            'output_directory': output_dir,
            'report_path': report_path
        }

    def _analyze_content(self, content):
        """Analyze file content for patterns and statistics"""
        analysis = {
            'byte_frequency': {},
            'byte_patterns': [],
            'ascii_percentage': 0,
            'null_byte_sequences': [],
            'entropy_blocks': []
        }
        
        # Byte frequency analysis
        for byte in content:
            analysis['byte_frequency'][byte] = analysis['byte_frequency'].get(byte, 0) + 1
        
        # Calculate ASCII percentage
        ascii_count = sum(1 for b in content if 32 <= b <= 126)
        analysis['ascii_percentage'] = (ascii_count / len(content)) * 100 if content else 0
        
        # Analyze entropy in blocks
        block_size = 1024
        for i in range(0, len(content), block_size):
            block = content[i:i+block_size]
            entropy = self._calculate_block_entropy(block)
            analysis['entropy_blocks'].append((i, entropy))
        
        return analysis

    def _calculate_block_entropy(self, block):
        """Calculate entropy for a block of bytes"""
        if not block:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = block.count(x) / len(block)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy

    def _create_visualizations(self, analysis_results):
        """Create all visualizations for the analysis results"""
        visualizations = {}
        
        # Timeline visualization
        visualizations['timeline'] = self._create_timeline_visualization(analysis_results)
        
        # Byte frequency visualization
        visualizations['byte_freq'] = self._create_byte_frequency_plot(analysis_results)
        
        # Entropy map visualization
        visualizations['entropy_map'] = self._create_entropy_map(analysis_results)
        
        # File composition visualization
        visualizations['composition'] = self._create_composition_plot(analysis_results)
        
        return visualizations

    def _create_timeline_visualization(self, analysis_results):
        """Create an interactive timeline visualization"""
        dates = [
            analysis_results['file_info']['created'],
            analysis_results['file_info']['modified'],
            analysis_results['file_info']['accessed']
        ]
        events = ['Created', 'Modified', 'Accessed']
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=dates,
            y=events,
            mode='markers+text',
            name='File Events',
            text=events,
            textposition='middle right',
            marker=dict(size=12, symbol='diamond')
        ))
        
        fig.update_layout(
            title='File Timeline',
            xaxis_title='Date/Time',
            yaxis_title='Event',
            showlegend=False,
            height=300
        )
        
        return fig

    def _create_byte_frequency_plot(self, analysis_results):
        """Create byte frequency visualization"""
        freq = analysis_results['content_analysis']['byte_frequency']
        bytes_vals = list(range(256))
        frequencies = [freq.get(b, 0) for b in bytes_vals]
        
        fig = go.Figure()
        
        # Add byte frequency histogram
        fig.add_trace(go.Bar(
            x=bytes_vals,
            y=frequencies,
            name='Byte Frequency',
            marker_color='rgba(58, 71, 80, 0.6)'
        ))
        
        fig.update_layout(
            title='Byte Frequency Distribution',
            xaxis_title='Byte Value',
            yaxis_title='Frequency',
            height=300,
            showlegend=False
        )
        
        return fig

    def _create_entropy_map(self, analysis_results):
        """Create entropy map visualization"""
        entropy_blocks = analysis_results['content_analysis']['entropy_blocks']
        positions, entropies = zip(*entropy_blocks) if entropy_blocks else ([], [])
        
        fig = go.Figure()
        
        fig.add_trace(go.Scatter(
            x=[p/1024 for p in positions],  # Convert to KB
            y=entropies,
            mode='lines',
            name='Entropy',
            line=dict(color='rgb(31, 119, 180)')
        ))
        
        fig.update_layout(
            title='File Entropy Map',
            xaxis_title='Position (KB)',
            yaxis_title='Entropy',
            height=300,
            showlegend=False
        )
        
        return fig

    def _create_composition_plot(self, analysis_results):
        """Create file composition visualization"""
        ascii_percent = analysis_results['content_analysis']['ascii_percentage']
        binary_percent = 100 - ascii_percent
        
        fig = go.Figure()
        
        fig.add_trace(go.Pie(
            labels=['ASCII', 'Binary'],
            values=[ascii_percent, binary_percent],
            hole=.3,
            marker=dict(
                colors=['rgb(158,202,225)', 'rgb(94,158,217)']
            )
        ))
        
        fig.update_layout(
            title='File Composition',
            height=300,
            showlegend=True
        )
        
        return fig

    def _format_size(self, size_bytes):
        """Format file size in human-readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"

    def _get_risk_color(self, risk_level):
        """Get Bootstrap color class for risk level"""
        return {
            'low': 'success',
            'medium': 'warning',
            'high': 'danger'
        }.get(risk_level, 'secondary')

    def _format_warnings(self, warnings):
        """Format security warnings as HTML"""
        if not warnings:
            return '<p>No security warnings detected.</p>'
        
        warnings_html = ['<h5>Warnings:</h5>', '<ul>']
        for warning in warnings:
            warnings_html.append(f'<li class="text-warning">{warning}</li>')
        warnings_html.append('</ul>')
        return '\n'.join(warnings_html)

    def _format_patterns(self, patterns):
        """Format suspicious patterns as HTML"""
        if not patterns:
            return '<p>No suspicious patterns detected.</p>'
        
        patterns_html = ['<h5>Suspicious Patterns:</h5>', '<ul>']
        for pattern in patterns:
            patterns_html.append(f'<li class="text-danger">{pattern}</li>')
        patterns_html.append('</ul>')
        return '\n'.join(patterns_html)

    def _format_metadata_section(self, metadata):
        """Format metadata section as HTML"""
        if not metadata:
            return ''
        
        html = ['<h2>File Metadata</h2>', '<div class="card mb-4">', '<div class="card-body">']        
        if 'image' in metadata:
            html.extend([
                '<h5>Image Information:</h5>',
                f'<p><strong>Format:</strong> {metadata["image"]["format"]}</p>',
                f'<p><strong>Mode:</strong> {metadata["image"]["mode"]}</p>',
                f'<p><strong>Size:</strong> {metadata["image"]["size"][0]}x{metadata["image"]["size"][1]}</p>'
            ])
            
            if metadata['image']['exif']:
                html.extend(['<h5>EXIF Data:</h5>', '<ul>'])
                for tag, value in metadata['image']['exif'].items():
                    html.append(f'<li><strong>{tag}:</strong> {value}</li>')
                html.append('</ul>')
        
        html.extend(['</div>', '</div>'])
        return '\n'.join(html)

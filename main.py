import os
import hashlib
import json
import mimetypes
import zipfile
import logging
import platform
import shutil
import re
import sqlite3
import time
import csv
import base64
import tempfile
import threading
import queue
import math
from datetime import datetime
from PIL import Image, ExifTags
from jinja2 import Template
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, jsonify, send_file
from forensics_tool import ForensicTool
from url_analyzer import URLAnalyzer
from werkzeug.utils import secure_filename
import plotly.graph_objects as go
import plotly.utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('digital_forensics.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global variables
evidence_queue = queue.Queue()
analysis_results = []
analysis_lock = threading.Lock()
stop_threads = threading.Event()

class FileSignatures:
    """
    File signature database for file type identification
    """
    SIGNATURES = {
        # Images
        b'\xff\xd8\xff': {'ext': '.jpg', 'mime': 'image/jpeg'},
        b'\x89PNG\r\n\x1a\n': {'ext': '.png', 'mime': 'image/png'},
        b'GIF8': {'ext': '.gif', 'mime': 'image/gif'},
        b'BM': {'ext': '.bmp', 'mime': 'image/bmp'},
        
        # Documents
        b'%PDF': {'ext': '.pdf', 'mime': 'application/pdf'},
        b'\xd0\xcf\x11\xe0': {'ext': '.doc', 'mime': 'application/msword'},  # Office documents
        b'PK\x03\x04': {'ext': '.zip', 'mime': 'application/zip'},  # ZIP archives and Office XML
        
        # Executables
        b'MZ': {'ext': '.exe', 'mime': 'application/x-msdownload'},
        b'\x7fELF': {'ext': '.elf', 'mime': 'application/x-executable'},
        
        # Database
        b'SQLite format': {'ext': '.db', 'mime': 'application/x-sqlite3'},
        
        # Audio/Video
        b'ID3': {'ext': '.mp3', 'mime': 'audio/mpeg'},
        b'\x00\x00\x00\x18ftypmp4': {'ext': '.mp4', 'mime': 'video/mp4'},
        b'RIFF': {'ext': '.avi', 'mime': 'video/x-msvideo'},
    }
    
    @staticmethod
    def identify_file_type(file_path):
        """
        Identify file type based on file signatures/magic numbers
        """
        try:
            with open(file_path, 'rb') as f:
                file_header = f.read(20)  # Read first 20 bytes for signature
            
            for signature, info in FileSignatures.SIGNATURES.items():
                if file_header.startswith(signature):
                    return info['mime'], info['ext']
            
            # Fall back to mimetypes if no signature match
            mime_type, _ = mimetypes.guess_type(file_path)
            return mime_type, os.path.splitext(file_path)[1]
        except Exception as e:
            logger.error(f"Error identifying file type: {e}")
            return None, None


class SecurityAnalysis:
    """
    Security analysis for potentially malicious files
    """
    @staticmethod
    def analyze_file_security(file_path):
        """
        Perform security analysis on a file using multiple heuristics
        """
        try:
            file_size = os.path.getsize(file_path)
            suspicious_indicators = []
            
            # Get file type
            mime_type, extension = FileSignatures.identify_file_type(file_path)
            if not mime_type:
                mime_type = mimetypes.guess_type(file_path)[0] or "unknown"
                extension = os.path.splitext(file_path)[1].lower()
            
            # Read file content for analysis
            try:
                with open(file_path, 'rb') as f:
                    content = f.read(1024 * 1024)  # Read first 1MB for analysis
                    try:
                        text_content = content.decode('utf-8', errors='ignore')
                    except:
                        text_content = ""
            except Exception as e:
                return {
                    "status": "error",
                    "details": f"Could not read file for analysis: {str(e)}"
                }
            
            # Check for file extension mismatch
            if mime_type != "unknown":
                expected_ext = mimetypes.guess_extension(mime_type)
                if expected_ext and extension != expected_ext and extension != ".bin":
                    suspicious_indicators.append(f"File extension mismatch: {extension} doesn't match content type {mime_type}")
            
            # Check for suspicious file size
            if file_size == 0:
                suspicious_indicators.append("Empty file")
            elif mime_type in ['application/x-executable', 'application/x-msdownload'] and file_size < 5000:
                suspicious_indicators.append("Suspiciously small executable file")
            elif mime_type and mime_type.startswith('text/') and file_size > 15 * 1024 * 1024:  # 15MB
                suspicious_indicators.append("Unusually large text file")
            
            # Check for executable files with embedded scripts
            if mime_type in ['application/x-executable', 'application/x-msdownload', 'application/octet-stream']:
                script_patterns = [
                    rb'<script', rb'function\(', rb'eval\(', rb'document\.write',
                    rb'powershell', rb'cmd\.exe', rb'cmd /c', rb'cscript', 
                    rb'wscript', rb'rundll32', rb'regsvr32'
                ]
                
                for pattern in script_patterns:
                    if pattern in content.lower():
                        suspicious_indicators.append(f"Executable contains script code: {pattern.decode('utf-8', errors='ignore')}")
            
            # Check for obfuscated JavaScript
            if mime_type in ['text/html', 'text/javascript', 'application/javascript']:
                js_obfuscation_patterns = [
                    r'eval\s*\(\s*atob\s*\(', r'eval\s*\(\s*decodeURIComponent\s*\(',
                    r'String\.fromCharCode\(', r'unescape\s*\(', r'\"\+\"',
                    r'\\x[0-9a-f]{2}', r'\\u[0-9a-f]{4}'
                ]
                
                obfuscation_count = 0
                for pattern in js_obfuscation_patterns:
                    matches = re.findall(pattern, text_content)
                    obfuscation_count += len(matches)
                
                if obfuscation_count > 10:
                    suspicious_indicators.append(f"Potentially obfuscated JavaScript with {obfuscation_count} suspicious patterns")
            
            # Check for PHP webshells
            if mime_type == 'text/x-php' or extension == '.php':
                php_malicious_patterns = [
                    r'base64_decode\s*\(', r'eval\s*\(', r'system\s*\(', r'exec\s*\(',
                    r'passthru\s*\(', r'shell_exec\s*\(', r'phpinfo\s*\(', r'\$_POST\s*\[',
                    r'\$_GET\s*\[', r'\$_REQUEST\s*\[', r'assert\s*\('
                ]
                
                malicious_func_count = 0
                for pattern in php_malicious_patterns:
                    matches = re.findall(pattern, text_content)
                    malicious_func_count += len(matches)
                
                if malicious_func_count > 5:
                    suspicious_indicators.append(f"Potential PHP webshell with {malicious_func_count} suspicious functions")
            
            # Check for suspicious PE file characteristics
            if mime_type in ['application/x-executable', 'application/x-msdownload']:
                pe_suspicious_strings = [
                    b'VirtualAlloc', b'CreateProcess', b'WriteProcessMemory', b'CreateRemoteThread',
                    b'RegCreateKey', b'InternetOpen', b'HttpSendRequest', b'WinExec',
                    b'ShellExecute', b'CreateService', b'StartService'
                ]
                
                suspicious_api_count = 0
                for api in pe_suspicious_strings:
                    if api in content:
                        suspicious_api_count += 1
                
                if suspicious_api_count > 3:
                    suspicious_indicators.append(f"Executable using {suspicious_api_count} potentially suspicious Windows APIs")
            
            # Check for hidden data in images
            if mime_type and mime_type.startswith('image/'):
                # Simple check for potential steganography
                if b'PK' in content[-1024:]:  # ZIP signature at the end of the file
                    suspicious_indicators.append("Potential hidden ZIP data in image (steganography)")
                
            # Summarize results
            if not suspicious_indicators:
                return {
                    "status": "probably_clean",
                    "details": "No obvious suspicious characteristics detected",
                    "risk_level": "low"
                }
            else:
                # Determine risk level based on number and type of indicators
                risk_level = "medium" if len(suspicious_indicators) < 3 else "high"
                return {
                    "status": "suspicious",
                    "details": "Potentially suspicious file",
                    "indicators": suspicious_indicators,
                    "risk_level": risk_level
                }
                
        except Exception as e:
            logger.error(f"Error during security analysis: {e}")
            return {
                "status": "error",
                "details": f"Error during security analysis: {str(e)}",
                "risk_level": "unknown"
            }


class MalwareAnalysis:
    """
    Enhanced malware analysis capabilities
    """
    # Database of known malware signatures and their types
    MALWARE_SIGNATURES = {
        # Virus signatures
        b'\x31\xc0\x50\x68\x2f\x2f\x73\x68': {"type": "virus", "name": "ExampleVirus1"},
        b'\xeb\x1f\x5e\x89\x76\x08\x31\xc0': {"type": "virus", "name": "ExampleVirus2"},
        
        # Worm signatures
        b'\x68\x65\x6c\x6c\x6f\x20\x77\x6f': {"type": "worm", "name": "ExampleWorm1"},
        b'\x6d\x61\x6c\x77\x61\x72\x65\x20': {"type": "worm", "name": "ExampleWorm2"},
        
        # Trojan signatures
        b'\x74\x72\x6f\x6a\x61\x6e\x20\x68': {"type": "trojan", "name": "ExampleTrojan1"},
        b'\x68\x61\x63\x6b\x65\x72\x20\x74': {"type": "trojan", "name": "ExampleTrojan2"},
        
        # Ransomware signatures
        b'\x72\x61\x6e\x73\x6f\x6d\x77\x61': {"type": "ransomware", "name": "ExampleRansomware1"},
        b'\x65\x6e\x63\x72\x79\x70\x74\x20': {"type": "ransomware", "name": "ExampleRansomware2"},
    }

    @staticmethod
    def scan_for_malware(file_path):
        """
        Scan a file for known malware signatures and provide detailed information.
        """
        try:
            with open(file_path, 'rb') as f:
                content = f.read()

            detected_malware = []
            for signature, malware_info in MalwareAnalysis.MALWARE_SIGNATURES.items():
                if signature in content:
                    detected_malware.append({
                        "type": malware_info["type"],
                        "name": malware_info["name"],
                        "signature": signature.hex(),
                    })

            if detected_malware:
                return {
                    "infected": True,
                    "details": detected_malware,
                    "message": f"File is infected with {len(detected_malware)} malware(s)."
                }
            else:
                return {
                    "infected": False,
                    "details": [],
                    "message": "No known malware detected."
                }

        except Exception as e:
            logger.error(f"Error scanning for malware: {e}")
            return {
                "infected": "unknown",
                "details": [],
                "message": f"Error during malware scan: {str(e)}"
            }


class MetadataExtractor:
    @staticmethod
    def extract_metadata(file_path):
        """
        Extract metadata from a file, including malware detection results
        """
        try:
            # Get basic file information
            file_stat = os.stat(file_path)
            file_name = os.path.basename(file_path)
            file_extension = os.path.splitext(file_name)[1].lower()
            file_size = file_stat.st_size
            
            # Basic metadata common to all files
            metadata = {
                "file_name": file_name,
                "extension": file_extension,
                "size_bytes": file_size,
                "size_human": MetadataExtractor.format_file_size(file_size),
                "created_time": datetime.fromtimestamp(file_stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
                "modified_time": datetime.fromtimestamp(file_stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "accessed_time": datetime.fromtimestamp(file_stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
                "sha256": MetadataExtractor.calculate_file_hash(file_path, "sha256"),
                "md5": MetadataExtractor.calculate_file_hash(file_path, "md5"),
                "malware_scan": MalwareAnalysis.scan_for_malware(file_path),  # Add malware scan results
            }
            
            # Get MIME type
            mime_type, _ = FileSignatures.identify_file_type(file_path)
            if not mime_type:
                mime_type = mimetypes.guess_type(file_path)[0] or "unknown"
            metadata["mime_type"] = mime_type
            
            # Extract type-specific metadata
            if mime_type and mime_type.startswith('image/'):
                metadata["image_metadata"] = MetadataExtractor.extract_image_metadata(file_path)
            elif mime_type in ['application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']:
                metadata["document_metadata"] = MetadataExtractor.extract_document_metadata(file_path)
            elif mime_type == 'application/x-sqlite3' or file_extension == '.db':
                metadata["sqlite_metadata"] = MetadataExtractor.extract_sqlite_metadata(file_path)
            elif mime_type == 'application/zip' or file_extension in ['.zip', '.jar', '.apk']:
                metadata["zip_content"] = MetadataExtractor.extract_zip_content(file_path)
            
            # Perform security analysis
            metadata["security_analysis"] = SecurityAnalysis.analyze_file_security(file_path)
            
            return metadata
        except Exception as e:
            logger.error(f"Error extracting metadata from {file_path}: {e}")
            return {"error": str(e)}


class EvidenceProcessor:
    """
    Main class for processing digital evidence
    """
    def __init__(self, case_id, evidence_path, output_dir, num_workers=4):
        self.case_id = case_id
        self.evidence_path = evidence_path
        self.output_dir = output_dir
        self.num_workers = num_workers
        self.processed_files = 0
        self.start_time = None
        self.results_db = os.path.join(output_dir, f"{case_id}_results.sqlite")
        
        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)
        
        # Initialize results database
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize SQLite database for storing results"""
        conn = sqlite3.connect(self.results_db)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT UNIQUE,
            file_name TEXT,
            file_extension TEXT,
            file_size INTEGER,
            mime_type TEXT,
            sha256 TEXT,
            md5 TEXT,
            created_time TEXT,
            modified_time TEXT,
            accessed_time TEXT,
            risk_level TEXT,
            analysis_time TEXT,
            malware_scan TEXT  -- Add this column
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            indicator TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
        ''')
        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_id INTEGER,
            metadata_type TEXT,
            metadata_key TEXT,
            metadata_value TEXT,
            FOREIGN KEY (file_id) REFERENCES files(id)
        )
        ''')
        
        conn.commit()
        conn.close()
    
    def _worker_thread(self):
        """Worker thread for processing files"""
        while not stop_threads.is_set():
            try:
                file_path = evidence_queue.get(timeout=1)
                logger.info(f"Processing file: {file_path}")
                
                # Extract metadata and analyze file
                metadata = MetadataExtractor.extract_metadata(file_path)
                
                # Store results in database
                self._store_results(file_path, metadata)
                
                # Store results for report generation
                with analysis_lock:
                    analysis_results.append(metadata)
                    self.processed_files += 1
                
                evidence_queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error processing file: {e}")
                evidence_queue.task_done()
    
    def _store_results(self, file_path, metadata):
        """Store analysis results in SQLite database"""
        try:
            conn = sqlite3.connect(self.results_db)
            cursor = conn.cursor()
            
            # Insert basic file info
            cursor.execute('''
            INSERT INTO files (
                file_path, file_name, file_extension, file_size, mime_type, 
                sha256, md5, created_time, modified_time, accessed_time, 
                risk_level, analysis_time, malware_scan
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_path,
                metadata.get('file_name', ''),
                metadata.get('extension', ''),
                metadata.get('size_bytes', 0),
                metadata.get('mime_type', 'unknown'),
                metadata.get('sha256', ''),
                metadata.get('md5', ''),
                metadata.get('created_time', ''),
                metadata.get('modified_time', ''),
                metadata.get('accessed_time', ''),
                metadata.get('security_analysis', {}).get('risk_level', 'unknown'),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                json.dumps(metadata.get('malware_scan', {}))  # Store malware scan results as JSON
            ))
            
            file_id = cursor.lastrowid
            
            # Insert security indicators
            security_analysis = metadata.get('security_analysis', {})
            if 'indicators' in security_analysis:
                for indicator in security_analysis['indicators']:
                    cursor.execute('''
                    INSERT INTO security_indicators (file_id, indicator)
                    VALUES (?, ?)
                    ''', (file_id, indicator))
            
            # Insert type-specific metadata
            for metadata_type in ['image_metadata', 'document_metadata', 'sqlite_metadata', 'zip_content']:
                if metadata_type in metadata:
                    self._store_nested_metadata(cursor, file_id, metadata_type, metadata[metadata_type])
            
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Error storing results for {file_path}: {e}")
    
    def _store_nested_metadata(self, cursor, file_id, metadata_type, metadata_dict, parent_key=''):
        """Recursively store nested metadata in the database"""
        if isinstance(metadata_dict, dict):
            for key, value in metadata_dict.items():
                full_key = f"{parent_key}.{key}" if parent_key else key
                
                if isinstance(value, (dict, list)):
                    self._store_nested_metadata(cursor, file_id, metadata_type, value, full_key)
                else:
                    # Convert value to string for storage
                    str_value = str(value)
                    if len(str_value) > 1000:  # Limit very long values
                        str_value = str_value[:997] + "..."
                    
                    cursor.execute('''
                    INSERT INTO metadata (file_id, metadata_type, metadata_key, metadata_value)
                    VALUES (?, ?, ?, ?)
                    ''', (file_id, metadata_type, full_key, str_value))
        elif isinstance(metadata_dict, list):
            for i, item in enumerate(metadata_dict):
                item_key = f"{parent_key}[{i}]"
                self._store_nested_metadata(cursor, file_id, metadata_type, item, item_key)
    
    def _collect_files(self, directory):
        """Collect all files recursively from a directory"""
        file_count = 0
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    if os.path.isfile(file_path):
                        evidence_queue.put(file_path)
                        file_count += 1
                except Exception as e:
                    logger.error(f"Error adding file {file_path} to queue: {e}")
        return file_count
    
    def process_evidence(self):
        """Main method to process all evidence"""
        logger.info(f"Starting evidence processing for case {self.case_id}")
        logger.info(f"Source: {self.evidence_path}")
        logger.info(f"Output directory: {self.output_dir}")
        
        self.start_time = time.time()
        total_files = self._collect_files(self.evidence_path)
        logger.info(f"Found {total_files} files to process")
        
        # Create and start worker threads
        threads = []
        for _ in range(self.num_workers):
            thread = threading.Thread(target=self._worker_thread)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        # Display progress
        while evidence_queue.qsize() > 0:
            remaining = evidence_queue.qsize()
            processed = total_files - remaining
            progress = (processed / total_files) * 100 if total_files > 0 else 0
            elapsed = time.time() - self.start_time
            
            logger.info(f"Progress: {processed}/{total_files} files ({progress:.1f}%) - Elapsed time: {elapsed:.1f}s")
            time.sleep(5)
        
        # Wait for all tasks to complete
        evidence_queue.join()
        
        # Signal threads to exit and wait for them
        stop_threads.set()
        for thread in threads:
            thread.join()
        
        # Generate report
        self.generate_report()
        
        # Calculate final stats
        elapsed_time = time.time() - self.start_time
        logger.info(f"Evidence processing complete for case {self.case_id}")
        logger.info(f"Processed {self.processed_files} files in {elapsed_time:.1f} seconds")
        logger.info(f"Results stored in {self.output_dir}")
        
        return {
            "case_id": self.case_id,
            "processed_files": self.processed_files,
            "elapsed_time": elapsed_time,
            "output_directory": self.output_dir
        }
    
    def generate_report(self):
        """Generate HTML, CSV, and JSON reports"""
        try:
            # Connect to the results database
            conn = sqlite3.connect(self.results_db)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Get summary statistics
            cursor.execute("SELECT COUNT(*) as total FROM files")
            total_files = cursor.fetchone()['total']
            
            cursor.execute("SELECT COUNT(*) as count, risk_level FROM files GROUP BY risk_level")
            risk_summary = cursor.fetchall()
            
            cursor.execute("SELECT COUNT(*) as count, mime_type FROM files GROUP BY mime_type ORDER BY count DESC LIMIT 10")
            file_types = cursor.fetchall()
            
            cursor.execute("""
            SELECT f.id, f.file_path, f.file_name, f.file_size, f.mime_type, f.risk_level, f.sha256, f.malware_scan
            FROM files f 
            WHERE f.risk_level = 'high' 
            ORDER BY f.file_size DESC
            LIMIT 50
            """)
            high_risk_files = cursor.fetchall()
            
            # Generate CSV report of all files
            csv_path = os.path.join(self.output_dir, f"{self.case_id}_files.csv")
            with open(csv_path, 'w', newline='') as csvfile:
                cursor.execute("""
                SELECT 
                    file_path, file_name, file_extension, file_size, 
                    mime_type, sha256, md5, created_time, modified_time, 
                    accessed_time, risk_level, malware_scan 
                FROM files
                """)
                
                rows = cursor.fetchall()
                if rows:
                    writer = csv.writer(csvfile)
                    # Add headers
                    writer.writerow([
                        "file_path", "file_name", "file_extension", "file_size", 
                        "mime_type", "sha256", "md5", "created_time", "modified_time", 
                        "accessed_time", "risk_level", "malware_scan"
                    ])
                    # Write rows
                    for row in rows:
                        writer.writerow([row[key] for key in row.keys()])
            
            # Generate CSV report of security indicators
            indicators_csv_path = os.path.join(self.output_dir, f"{self.case_id}_security_indicators.csv")
            with open(indicators_csv_path, 'w', newline='') as csvfile:
                cursor.execute("""
                SELECT 
                    f.file_path, f.file_name, f.risk_level, s.indicator
                FROM files f
                JOIN security_indicators s ON f.id = s.file_id
                ORDER BY f.risk_level DESC
                """)
                
                rows = cursor.fetchall()
                if rows:
                    writer = csv.writer(csvfile)
                    writer.writerow([key for key in rows[0].keys()])
                    for row in rows:
                        writer.writerow([row[key] for key in row.keys()])
            
            # Query malware scan results
            cursor.execute("SELECT file_path, file_name, malware_scan FROM files")
            malware_results = []
            for row in cursor.fetchall():
                malware_scan = json.loads(row['malware_scan'])  # Convert JSON string to dict
                malware_results.append({
                    "file_path": row['file_path'],
                    "file_name": row['file_name'],
                    "malware_scan": malware_scan
                })

            # Generate JSON report
            json_path = os.path.join(self.output_dir, f"{self.case_id}_report.json")
            with open(json_path, 'w') as jsonfile:
                json.dump({
                    "case_id": self.case_id,
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_files": total_files,
                    "risk_summary": [dict(row) for row in risk_summary],
                    "file_types": [dict(row) for row in file_types],
                    "high_risk_files": [dict(row) for row in high_risk_files],
                    "malware_results": malware_results,  # Add malware results
                }, jsonfile, indent=4)
            
            # Generate HTML report
            html_template = '''
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Digital Forensics Report - Case {{ case_id }}</title>
                <style>
                    body {
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        margin: 0;
                        padding: 20px;
                        color: #333;
                    }
                    h1, h2, h3 {
                        color: #2c3e50;
                    }
                    .container {
                        max-width: 1200px;
                        margin: 0 auto;
                    }
                    .header {
                        background-color: #34495e;
                        color: white;
                        padding: 20px;
                        margin-bottom: 20px;
                    }
                    .section {
                        margin-bottom: 30px;
                        padding: 20px;
                        background-color: #f9f9f9;
                        border-radius: 5px;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-bottom: 20px;
                    }
                    th, td {
                        padding: 12px 15px;
                        text-align: left;
                        border-bottom: 1px solid #ddd;
                    }
                    th {
                        background-color: #34495e;
                        color: white;
                    }
                    tr:nth-child(even) {
                        background-color: #f2f2f2;
                    }
                    .risk-high {
                        background-color: #ff6b6b;
                        color: white;
                        padding: 3px 8px;
                        border-radius: 3px;
                    }
                    .risk-medium {
                        background-color: #feca57;
                        padding: 3px 8px;
                        border-radius: 3px;
                    }
                    .risk-low {
                        background-color: #1dd1a1;
                        padding: 3px 8px;
                        border-radius: 3px;
                    }
                    .summary-box {
                        display: inline-block;
                        width: 200px;
                        padding: 15px;
                        margin: 10px;
                        background-color: #ecf0f1;
                        border-radius: 5px;
                        text-align: center;
                        box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                    }
                    .summary-number {
                        font-size: 24px;
                        font-weight: bold;
                        margin-bottom: 5px;
                    }
                    .file-type-chart {
                        width: 100%;
                        height: 300px;
                    }
                </style>
            </head>
            <body>
                <div class="header">
                    <div class="container">
                        <h1>Digital Forensics Report</h1>
                        <p>Case ID: {{ case_id }} | Generated: {{ timestamp }}</p>
                    </div>
                </div>
                
                <div class="container">
                    <div class="section">
                        <h2>Case Summary</h2>
                        <div class="summary-box">
                            <div class="summary-number">{{ total_files }}</div>
                            <div>Total Files Analyzed</div>
                        </div>
                        {% for risk in risk_summary %}
                        <div class="summary-box">
                            <div class="summary-number">{{ risk.count }}</div>
                            <div>{{ risk.risk_level|title }} Risk Files</div>
                        </div>
                        {% endfor %}
                        <div class="summary-box">
                            <div class="summary-number">{{ elapsed_time|round(1) }}s</div>
                            <div>Processing Time</div>
                        </div>
                    </div>
                        
                    <div class="section">
                        <h2>File Type Distribution</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>File Type</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for type in file_types %}
                                <tr>
                                    <td>{{ type.mime_type }}</td>
                                    <td>{{ type.count }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                        
                    {% if high_risk_files %}
                    <div class="section">
                        <h2>High Risk Files</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>File Name</th>
                                    <th>Path</th>
                                    <th>Size</th>
                                    <th>Type</th>
                                    <th>Risk Level</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for file in high_risk_files %}
                                <tr>
                                    <td>{{ file.file_name }}</td>
                                    <td>{{ file.file_path }}</td>
                                    <td>{{ file.file_size|filesizeformat }}</td>
                                    <td>{{ file.mime_type }}</td>
                                    <td><span class="risk-{{ file.risk_level }}">{{ file.risk_level|upper }}</span></td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                    {% endif %}
                        
                    <div class="section">
                        <h2>Malware Scan Results</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>File Name</th>
                                    <th>Status</th>
                                    <th>Infection Type</th>
                                    <th>Details</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for file in malware_results %}
                                <tr>
                                    <td>{{ file.file_name }}</td>
                                    <td>{{ "Infected" if file.malware_scan.infected else "Clean" }}</td>
                                    <td>{{ ", ".join(file.malware_scan.details.keys()) if file.malware_scan.infected else "N/A" }}</td>
                                    <td>{{ file.malware_scan.message }}</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                        
                    <div class="section">
                        <h2>Report Files</h2>
                        <ul>
                            <li><a href="{{ case_id }}_files.csv">Complete File List (CSV)</a></li>
                            <li><a href="{{ case_id }}_security_indicators.csv">Security Indicators (CSV)</a></li>
                            <li><a href="{{ case_id }}_results.sqlite">Full Analysis Database (SQLite)</a></li>
                        </ul>
                    </div>
                </div>
            </body>
            </html>
            '''
                
            # Render the HTML template
            template = Template(html_template)
            html_content = template.render(
                case_id=self.case_id,
                timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                total_files=total_files,
                risk_summary=risk_summary,
                file_types=file_types,
                high_risk_files=high_risk_files,
                malware_results=malware_results,  # Pass malware results to the template
                elapsed_time=time.time() - self.start_time
            )
                
            # Write HTML report
            html_path = os.path.join(self.output_dir, f"{self.case_id}_report.html")
            with open(html_path, 'w') as html_file:
                html_file.write(html_content)
                
            conn.close()
            logger.info(f"Generated reports in {self.output_dir}")
                
        except Exception as e:
            logger.error(f"Error generating report: {e}")


class AdvancedAnalysis:
    """
    Advanced analysis techniques for digital forensics
    """
        
    @staticmethod
    def detect_encryption(file_path):
        """
        Detect potential file encryption using entropy analysis
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read(4096)  # Read first 4KB for analysis
                
            if not data:
                return {"encrypted": False, "reason": "Empty file"}
                
            # Calculate Shannon entropy
            entropy = 0
            byte_counts = {}
            for byte in data:
                if byte not in byte_counts:
                    byte_counts[byte] = 0
                byte_counts[byte] += 1
                
            for count in byte_counts.values():
                probability = count / len(data)
                entropy -= probability * math.log2(probability)
                
            # Check for high entropy (typical for encrypted/compressed data)
            if entropy > 7.5:  # Very high entropy, close to 8 (maximum for bytes)
                return {"encrypted": True, "reason": f"High entropy ({entropy:.2f})", "entropy": entropy}
            elif entropy > 6.5:  # Moderately high entropy
                return {"encrypted": "maybe", "reason": f"Moderate-high entropy ({entropy:.2f})", "entropy": entropy}
            else:
                return {"encrypted": False, "reason": f"Low entropy ({entropy:.2f})", "entropy": entropy}
                
        except Exception as e:
            logger.error(f"Error detecting encryption: {e}")
            return {"encrypted": "unknown", "reason": f"Error: {str(e)}"}
    
    @staticmethod
    def search_for_regex_patterns(file_path, patterns):
        """
        Search for regex patterns in files (PII, credentials, etc.)
        """
        try:
            # Compile regex patterns
            compiled_patterns = {}
            for name, pattern in patterns.items():
                compiled_patterns[name] = re.compile(pattern)
                
            # Read file content
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                
            # Search for patterns
            results = {}
            for name, pattern in compiled_patterns.items():
                matches = pattern.findall(content)
                if matches:
                    # Limit number of matches to avoid huge results
                    limited_matches = matches[:10]
                    results[name] = limited_matches
                
            return results
        except Exception as e:
            logger.error(f"Error searching for patterns: {e}")
            return {"error": str(e)}
        
    @staticmethod
    def detect_deleted_files(directory):
        """
        Detect potentially recoverable deleted files (simplified)
        Note: Real implementation would use direct disk access methods
        """
        # In a real implementation, this would use forensic libraries for direct disk access
        return {
            "note": "Deleted file detection requires direct disk access. This would be implemented with specialized forensic libraries."
        }


class TimelineAnalysis:
    """
    Create and analyze file activity timelines
    """
        
    @staticmethod
    def create_timeline(db_path):
        """
        Create timeline from file timestamps in database
        """
        try:
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
                
            # Query all file timestamps
            cursor.execute("""
                SELECT 
                    file_path, file_name, 
                    created_time, modified_time, accessed_time,
                    mime_type, risk_level
                FROM files
                ORDER BY modified_time
            """)
                
            files = cursor.fetchall()
            timeline = []
                
            for file in files:
                # Add creation event
                if file['created_time']:
                    timeline.append({
                        'timestamp': file['created_time'],
                        'event_type': 'created',
                        'file_path': file['file_path'],
                        'file_name': file['file_name'],
                        'mime_type': file['mime_type'],
                        'risk_level': file['risk_level']
                    })
                    
                # Add modification event
                if file['modified_time']:
                    timeline.append({
                        'timestamp': file['modified_time'],
                        'event_type': 'modified',
                        'file_path': file['file_path'],
                        'file_name': file['file_name'],
                        'mime_type': file['mime_type'],
                        'risk_level': file['risk_level']
                    })
                    
                # Add access event
                if file['accessed_time']:
                    timeline.append({
                        'timestamp': file['accessed_time'],
                        'event_type': 'accessed',
                        'file_path': file['file_path'],
                        'file_name': file['file_name'],
                        'mime_type': file['mime_type'],
                        'risk_level': file['risk_level']
                    })
                
            # Sort timeline by timestamp
            timeline.sort(key=lambda x: x['timestamp'])
                
            conn.close()
            return timeline
            
        except Exception as e:
            logger.error(f"Error creating timeline: {e}")
            return {"error": str(e)}
        
    @staticmethod
    def detect_anomalies(timeline):
        """
        Detect timeline anomalies that may indicate suspicious activity
        """
        try:
            anomalies = []
                
            # Group timeline events by date
            events_by_date = {}
            for event in timeline:
                date = event['timestamp'].split()[0]  # Extract just the date part
                if date not in events_by_date:
                    events_by_date[date] = []
                events_by_date[date].append(event)
                
            # Check for dates with unusual activity volumes
            event_counts = {date: len(events) for date, events in events_by_date.items()}
            if event_counts:
                avg_events = sum(event_counts.values()) / len(event_counts)
                std_dev = (sum((count - avg_events) ** 2 for count in event_counts.values()) / len(event_counts)) ** 0.5
                    
                # Flag dates with activity > avg + 2*std_dev as anomalous
                for date, count in event_counts.items():
                    if count > avg_events + 2 * std_dev:
                        anomalies.append({
                            'type': 'high_activity_date',
                            'date': date,
                            'event_count': count,
                            'average_count': avg_events,
                            'description': f"Unusually high file activity on {date} ({count} events, average is {avg_events:.1f})"
                        })
                
            # Check for timestamp backdating (files with creation times after modification times)
            for event in timeline:
                if event['event_type'] == 'created':
                    created_time = event['timestamp']
                    file_path = event['file_path']
                        
                    # Look for modification events for this file
                    for mod_event in timeline:
                        if mod_event['event_type'] == 'modified' and mod_event['file_path'] == file_path:
                            modified_time = mod_event['timestamp']
                            if created_time > modified_time:
                                anomalies.append({
                                    'type': 'timestamp_anomaly',
                                    'file_path': file_path,
                                    'created_time': created_time,
                                    'modified_time': modified_time,
                                    'description': f"File has creation time after modification time (created: {created_time}, modified: {modified_time})"
                                })
                
            return anomalies
                
        except Exception as e:
            logger.error(f"Error detecting timeline anomalies: {e}")
            return {"error": str(e)}


class DataRecovery:
    """
    Tools for recovering deleted data
    """
        
    @staticmethod
    def carve_deleted_files(disk_image, output_dir, file_types=None):
        """
        Carve deleted files from a disk image
        Note: In a real implementation, this would use forensic carving libraries
        """
        # This is a placeholder. In a real implementation, 
        # this would use libraries like scalpel, foremost, etc.
        logger.info(f"File carving is a placeholder. Would carve {disk_image} for {file_types} to {output_dir}")
        return {
            "status": "simulated",
            "note": "File carving requires specialized forensic libraries and disk access."
        }
        
    @staticmethod
    def recover_corrupted_files(file_path, output_path):
        """
        Attempt to recover corrupted files
        """
        try:
            # Detect file type
            mime_type, _ = FileSignatures.identify_file_type(file_path)
            
            if not mime_type:
                logger.warning(f"Could not identify file type for {file_path}")
                return {"status": "failed", "reason": "Unknown file type"}
            
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            recovery_result = {"status": "attempt", "mime_type": mime_type}
            
            # Different recovery strategies based on file type
            if mime_type == 'image/jpeg':
                # For JPEG: Find start/end markers and reconstruct
                start_marker = b'\xff\xd8'
                end_marker = b'\xff\xd9'
                
                if start_marker not in content:
                    return {"status": "failed", "reason": "Missing JPEG start marker"}
                
                start_pos = content.find(start_marker)
                end_pos = content.rfind(end_marker)
                
                if end_pos > start_pos:
                    # Extract valid JPEG data
                    valid_data = content[start_pos:end_pos + 2]
                    with open(output_path, 'wb') as out_file:
                        out_file.write(valid_data)
                    recovery_result["status"] = "success"
                    recovery_result["notes"] = f"Extracted valid JPEG from positions {start_pos} to {end_pos + 2}"
                else:
                    recovery_result["status"] = "partial"
                    recovery_result["notes"] = "Could not find valid JPEG end marker"
            
            elif mime_type == 'application/pdf':
                # For PDF: Find PDF header and trailer
                if b'%PDF' in content and b'%%EOF' in content:
                    start_pos = content.find(b'%PDF')
                    end_pos = content.rfind(b'%%EOF')
                    
                    if end_pos > start_pos:
                        valid_data = content[start_pos:end_pos + 5]
                        with open(output_path, 'wb') as out_file:
                            out_file.write(valid_data)
                        recovery_result["status"] = "success"
                        recovery_result["notes"] = f"Extracted valid PDF from positions {start_pos} to {end_pos + 5}"
                    else:
                        recovery_result["status"] = "failed"
                        recovery_result["notes"] = "Invalid PDF structure"
                else:
                    recovery_result["status"] = "failed"
                    recovery_result["notes"] = "Missing PDF header or trailer"
            
            elif mime_type == 'application/zip' or mime_type.endswith('zip'):
                # For ZIP: Try to repair the central directory
                try:
                    temp_dir = tempfile.mkdtemp()
                    temp_zip = os.path.join(temp_dir, "temp.zip")
                    
                    # Copy potentially corrupted zip to temp location
                    shutil.copy(file_path, temp_zip)
                    
                    # Try to open and test the zip
                    with zipfile.ZipFile(temp_zip, 'r') as zf:
                        # Try a test read
                        for name in zf.namelist()[:1]:
                            zf.read(name)
                    
                    # If we get here, the zip may be valid or recoverable
                    shutil.copy(temp_zip, output_path)
                    recovery_result["status"] = "success"
                    recovery_result["notes"] = "ZIP file appears to be valid or was repaired"
                    
                except zipfile.BadZipFile:
                    recovery_result["status"] = "failed"
                    recovery_result["notes"] = "ZIP recovery failed - corrupt central directory"
                finally:
                    # Clean up temp directory
                    shutil.rmtree(temp_dir, ignore_errors=True)
            
            else:
                recovery_result["status"] = "unsupported"
                recovery_result["notes"] = f"Recovery for {mime_type} not supported"
            
            return recovery_result
            
        except Exception as e:
            logger.error(f"Error during file recovery: {e}")
            return {"status": "error", "reason": str(e)}


class MemoryForensics:
    """
    Memory forensics capabilities
    """
    
    @staticmethod
    def analyze_memory_dump(memory_dump_path):
        """
        Analyze a memory dump file
        Note: In a real implementation, this would use memory forensics libraries
        """
        # This is a placeholder. In a real implementation,
        # this would use libraries like Volatility
        return {
            "status": "simulated",
            "note": "Memory forensics would be implemented using specialized libraries like Volatility"
        }


class NetworkForensics:
    """
    Network forensics capabilities
    """
    
    @staticmethod
    def analyze_pcap(pcap_file):
        """
        Analyze network packet capture (PCAP) files
        Note: In a real implementation, this would use packet analysis libraries
        """
        # This is a placeholder. In a real implementation,
        # this would use libraries like pyshark, scapy, etc.
        return {
            "status": "simulated",
            "note": "PCAP analysis would be implemented using specialized network analysis libraries"
        }
    
    @staticmethod
    def extract_dns_queries(pcap_file):
        """
        Extract DNS queries from a PCAP file
        """
        # Placeholder for DNS extraction
        return {
            "status": "simulated",
            "note": "DNS query extraction would extract domain names from network traffic"
        }
    
    @staticmethod
    def extract_http_requests(pcap_file):
        """
        Extract HTTP requests from a PCAP file
        """
        # Placeholder for HTTP extraction
        return {
            "status": "simulated",
            "note": "HTTP request extraction would identify web traffic and URLs accessed"
        }


class ForensicTool:
    """
    Main class for the digital forensics tool
    """
    
    def __init__(self):
        """Initialize the forensic tool"""
        self.cases = {}
        self.version = "1.0.0"
        logger.info(f"Digital Forensics Tool v{self.version} initialized")
    
    def create_case(self, case_name, case_description="", investigator=""):
        """Create a new case"""
        case_id = f"case_{int(time.time())}"
        case_dir = os.path.join("cases", case_id)
        os.makedirs(case_dir, exist_ok=True)
        
        case_info = {
            "case_id": case_id,
            "case_name": case_name,
            "case_description": case_description,
            "investigator": investigator,
            "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "created",
            "evidence_items": [],
            "directory": case_dir
        }
        
        # Save case info to disk
        with open(os.path.join(case_dir, "case_info.json"), 'w') as f:
            json.dump(case_info, f, indent=4)
        
        self.cases[case_id] = case_info
        logger.info(f"Created case: {case_id} - {case_name}")
        
        return case_id
    
    def add_evidence(self, case_id, evidence_path, evidence_type="disk_image", description=""):
        """Add evidence to a case"""
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return {"error": "Case not found"}
        
        if not os.path.exists(evidence_path):
            logger.error(f"Evidence path {evidence_path} not found")
            return {"error": "Evidence path not found"}
        
        evidence_id = f"evidence_{int(time.time())}"
        
        evidence_info = {
            "evidence_id": evidence_id,
            "path": evidence_path,
            "type": evidence_type,
            "description": description,
            "added_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": "added",
            "hash_sha256": MetadataExtractor.calculate_file_hash(evidence_path) if os.path.isfile(evidence_path) else None
        }
        
        # Add to case
        self.cases[case_id]["evidence_items"].append(evidence_info)
        
        # Update case info file
        with open(os.path.join(self.cases[case_id]["directory"], "case_info.json"), 'w') as f:
            json.dump(self.cases[case_id], f, indent=4)
        
        logger.info(f"Added evidence {evidence_id} to case {case_id}")
        return evidence_id
    
    def process_evidence(self, case_id, evidence_id, num_workers=4):
        """Process evidence"""
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return {"error": "Case not found"}
        
        # Find evidence item
        evidence_item = None
        for item in self.cases[case_id]["evidence_items"]:
            if item["evidence_id"] == evidence_id:
                evidence_item = item
                break
        
        if not evidence_item:
            logger.error(f"Evidence {evidence_id} not found in case {case_id}")
            return {"error": "Evidence not found"}
        
        # Set up output directory
        output_dir = os.path.join(self.cases[case_id]["directory"], evidence_id)
        os.makedirs(output_dir, exist_ok=True)
        
        # Start evidence processing
        processor = EvidenceProcessor(
            case_id=evidence_id,
            evidence_path=evidence_item["path"],
            output_dir=output_dir,
            num_workers=num_workers
        )
        
        # Update evidence status
        evidence_item["status"] = "processing"
        with open(os.path.join(self.cases[case_id]["directory"], "case_info.json"), 'w') as f:
            json.dump(self.cases[case_id], f, indent=4)
        
        # Process evidence
        result = processor.process_evidence()
        
        # Update evidence with results
        evidence_item["status"] = "processed"
        evidence_item["processed_at"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        evidence_item["processing_results"] = result
        
        # Update case info file
        with open(os.path.join(self.cases[case_id]["directory"], "case_info.json"), 'w') as f:
            json.dump(self.cases[case_id], f, indent=4)
        
        logger.info(f"Processed evidence {evidence_id} in case {case_id}")
        return result
    
    def create_timeline(self, case_id, evidence_id):
        """Create timeline from evidence processing results"""
        if case_id not in self.cases:
            logger.error(f"Case {case_id} not found")
            return {"error": "Case not found"}
        
        # Find evidence item
        evidence_item = None
        for item in self.cases[case_id]["evidence_items"]:
            if item["evidence_id"] == evidence_id:
                evidence_item = item
                break
        
        if not evidence_item:
            logger.error(f"Evidence {evidence_id} not found in case {case_id}")
            return {"error": "Evidence not found"}
        
        # Check if evidence has been processed
        if evidence_item["status"] != "processed":
            logger.error(f"Evidence {evidence_id} has not been processed yet")
            return {"error": "Evidence not processed"}
        
        # Get results database path
        results_db = os.path.join(self.cases[case_id]["directory"], evidence_id, f"{evidence_id}_results.sqlite")
        if not os.path.exists(results_db):
            logger.error(f"Results database not found for evidence {evidence_id}")
            return {"error": "Results database not found"}
        
        # Create timeline
        timeline = TimelineAnalysis.create_timeline(results_db)
        
        if "error" in timeline:
            logger.error(f"Error creating timeline: {timeline['error']}")
            return {"error": timeline["error"]}
        
        # Save timeline to a JSON file
        timeline_path = os.path.join(self.cases[case_id]["directory"], evidence_id, f"{evidence_id}_timeline.json")
        try:
            with open(timeline_path, 'w') as f:
                json.dump(timeline, f, indent=4)
            logger.info(f"Timeline saved to {timeline_path}")
        except Exception as e:
            logger.error(f"Error saving timeline: {e}")
            return {"error": str(e)}
        
        # Detect anomalies in the timeline
        anomalies = TimelineAnalysis.detect_anomalies(timeline)
        
        if "error" in anomalies:
            logger.error(f"Error detecting anomalies: {anomalies['error']}")
            return {"error": anomalies["error"]}
        
        # Save anomalies to a JSON file
        anomalies_path = os.path.join(self.cases[case_id]["directory"], evidence_id, f"{evidence_id}_anomalies.json")
        try:
            with open(anomalies_path, 'w') as f:
                json.dump(anomalies, f, indent=4)
            logger.info(f"Anomalies saved to {anomalies_path}")
        except Exception as e:
            logger.error(f"Error saving anomalies: {e}")
            return {"error": str(e)}
        
        # Update evidence item with timeline and anomalies info
        evidence_item["timeline"] = timeline_path
        evidence_item["anomalies"] = anomalies_path
        
        # Update case info file
        with open(os.path.join(self.cases[case_id]["directory"], "case_info.json"), 'w') as f:
            json.dump(self.cases[case_id], f, indent=4)
        
        logger.info(f"Timeline and anomalies created for evidence {evidence_id}")
        return {
            "timeline": timeline_path,
            "anomalies": anomalies_path
        }


# --- Flask App Entrypoint Patch ---
try:
    from app import app
except ImportError:
    app = None

if __name__ == "__main__":
    if app:
        app.run(debug=True, port=5011)
    else:
        # Initialize the forensic tool
        tool = ForensicTool()

        # Ask the user for the case name and description
        case_name = input("Enter case name: ")
        case_description = input("Enter case description: ")
        investigator = input("Enter the investigator's name: ")

        # Create a new case
        case_id = tool.create_case(case_name, case_description, investigator)
        print(f"Created case with ID: {case_id}")

        # Ask the user for the evidence path
        evidence_path = input("Enter the path to the evidence (file or directory): ").strip()
        if not os.path.exists(evidence_path):
            print(f"Error: The path '{evidence_path}' does not exist.")
            exit(1)

        # Ask the user for the output directory
        output_dir = input("Enter the path to save the output files: ").strip()
        os.makedirs(output_dir, exist_ok=True)
    os.makedirs(output_dir, exist_ok=True)

    # Add evidence to the case
    evidence_id = tool.add_evidence(case_id, evidence_path, "disk_image", "User-provided evidence")
    print(f"Added evidence with ID: {evidence_id}")

    # Process the evidence
    print("Processing evidence...")
    result = tool.process_evidence(case_id, evidence_id)
    print(f"Evidence processing completed. Results saved in: {result['output_directory']}")

    # Create a timeline
    print("Creating timeline...")
    timeline_result = tool.create_timeline(case_id, evidence_id)
    if "error" in timeline_result:
        print(f"Error creating timeline: {timeline_result['error']}")
    else:
        print(f"Timeline saved to: {timeline_result['timeline']}")
        print(f"Anomalies saved to: {timeline_result['anomalies']}")

    # Display malware scan results
    print("\nMalware Scan Results:")

results_db = os.path.join(output_dir, f"{evidence_id}_results.sqlite")

if os.path.exists(results_db):
    conn = sqlite3.connect(results_db)
    cursor = conn.cursor()

    try:
        # Check if 'files' table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='files'")
        if cursor.fetchone():
            cursor.execute("SELECT file_path, malware_scan FROM files")
            for row in cursor.fetchall():
                file_path, malware_scan = row
                malware_scan = json.loads(malware_scan)
                print(f"\nFile: {file_path}")
                if malware_scan.get("infected") is True:
                    print("Status: Infected")
                    for malware in malware_scan["details"]:
                        print(f"  - Type: {malware['type']}, Name: {malware['name']}, Signature: {malware['signature']}")
                else:
                    print("Status: Clean")
        else:
            print("⚠️ No 'files' table found. Evidence might not have been processed properly.")
    except Exception as e:
        print(f"❌ Error reading malware scan results: {e}")
    finally:
        conn.close()
else:
    print("❌ Results database not found. Maybe processing failed.")

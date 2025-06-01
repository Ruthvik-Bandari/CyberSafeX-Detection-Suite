from flask import Flask, request, render_template, redirect, url_for, send_from_directory, jsonify
import os
import sys
import sqlite3
from werkzeug.utils import secure_filename
from datetime import datetime
from werkzeug.exceptions import NotFound
import json
import plotly
import plotly.graph_objects as go
import hashlib
import requests
import traceback

# Ensure current directory is in sys.path so local modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from forensics_tool import ForensicTool
from url_analyzer import URLAnalyzer

app = Flask(__name__)

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize the forensics tool
tool = ForensicTool()

# Database initialization
def init_db():
    with sqlite3.connect('forensics.db') as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS analysis_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                result TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

# Initialize database
init_db()

# Feature definitions
features = {
    'file-signature': {
        'title': 'File Signature Analysis',
        'icon': 'fingerprint',
        'description': 'Analyze file signatures and magic numbers to identify file types and potential forgeries.',
        'capabilities': [
            'File type identification',
            'Magic number analysis',
            'File structure validation',
            'Format verification'
        ]
    },
    'security': {
        'title': 'Security & Malware Detection',
        'icon': 'shield-alt',
        'description': 'Advanced malware detection and security analysis of files and URLs.',
        'capabilities': [
            'Malware signature detection',
            'Behavioral analysis',
            'Vulnerability scanning',
            'Security scoring'
        ]
    },
    'metadata': {
        'title': 'Metadata Extraction',
        'icon': 'info-circle',
        'description': 'Extract and analyze metadata from various file types.',
        'capabilities': [
            'EXIF data extraction',
            'Document metadata',
            'Creation/modification timestamps',
            'Author and system information'
        ]
    },
    'timeline': {
        'title': 'Timeline Analysis',
        'icon': 'clock',
        'description': 'Create and analyze timelines of file system activities.',
        'capabilities': [
            'Activity visualization',
            'Event correlation',
            'Anomaly detection',
            'Pattern analysis'
        ]
    },
    'memory': {
        'title': 'Memory Forensics',
        'icon': 'memory',
        'description': 'Analyze memory dumps for evidence and artifacts.',
        'capabilities': [
            'Process analysis',
            'Memory dump analysis',
            'Artifact recovery',
            'String extraction'
        ]
    }
}

@app.route('/feature/<feature_id>')
def feature(feature_id):
    if feature_id not in features:
        return redirect(url_for('index'))
    return render_template('feature.html', feature=features[feature_id], feature_id=feature_id)

@app.route('/dashboard')
def dashboard():
    with sqlite3.connect('forensics.db') as conn:
        c = conn.cursor()
        
        # Get analysis counts by type
        c.execute('''
            SELECT type, COUNT(*) as count 
            FROM analysis_history 
            GROUP BY type
        ''')
        analysis_counts = dict(c.fetchall())
        
        # Get recent analyses
        c.execute('''
            SELECT type, target, result, timestamp 
            FROM analysis_history 
            ORDER BY timestamp DESC LIMIT 5
        ''')
        recent_analyses = [{
            'type': row[0],
            'target': row[1],
            'result': json.loads(row[2]),
            'timestamp': row[3]
        } for row in c.fetchall()]
        
        # Create visualizations
        visualizations = {}
        
        # Analysis type distribution
        if analysis_counts:
            visualizations['type_distribution'] = {
                'data': [{
                    'type': 'pie',
                    'labels': list(analysis_counts.keys()),
                    'values': list(analysis_counts.values()),
                    'hole': 0.4
                }],
                'layout': {
                    'title': 'Analysis Distribution',
                    'height': 400,
                    'margin': {'t': 30, 'b': 0, 'l': 0, 'r': 0}
                }
            }
    
    return render_template('dashboard.html',
                         analysis_counts=analysis_counts,
                         recent_analyses=recent_analyses,
                         visualizations=visualizations)

@app.route('/history')
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    with sqlite3.connect('forensics.db') as conn:
        c = conn.cursor()
        
        # Get total count
        c.execute('SELECT COUNT(*) FROM analysis_history')
        total = c.fetchone()[0]
        
        # Get paginated results
        offset = (page - 1) * per_page
        c.execute('''
            SELECT id, type, target, result, timestamp 
            FROM analysis_history 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        ''', (per_page, offset))
        
        analyses = [{
            'id': row[0],
            'type': row[1],
            'target': row[2],
            'result': json.loads(row[3]),
            'timestamp': row[4]
        } for row in c.fetchall()]
    
    total_pages = (total + per_page - 1) // per_page
    
    return render_template('history.html',
                         analyses=analyses,
                         page=page,
                         total_pages=total_pages)
# End of features dictionary

@app.route('/')
def index():
    if request.method == "POST":
        case_name = request.form.get("case_name")
        description = request.form.get("description")
        investigator = request.form.get("investigator")
        file = request.files.get("evidence")

        if not (case_name and investigator and file):
            return render_template("index.html", error="Please fill all required fields.")

        # Create case and generate folder
        case_id = tool.create_case(case_name, description, investigator)
        case_dir = os.path.join(app.config['UPLOAD_FOLDER'], case_id)
        os.makedirs(case_dir, exist_ok=True)

        # Save evidence with safe filename and unique ID
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4().hex}_{filename}"
        file_path = os.path.join(case_dir, unique_filename)
        file.save(file_path)

        # Add and process evidence
        evidence_id = tool.add_evidence(case_id, file_path)
        result = tool.process_evidence(case_id, evidence_id)
        tool.create_timeline(case_id, evidence_id)

        # Report path
        report_path = os.path.join(result['output_directory'], f"{evidence_id}_report.html")
        return redirect(url_for('report', path=report_path))

    return render_template("index.html")

@app.route('/analyze-file', methods=['POST'])
def analyze_file():
    try:
        if 'file' not in request.files:
            return jsonify({
                'success': False,
                'error': 'No file uploaded'
            }), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({
                'success': False,
                'error': 'No file selected'
            }), 400
        
        # Save and analyze file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Get file info
            file_size = os.path.getsize(filepath)
            file_type = os.path.splitext(filename)[1]
            
            # Basic file analysis results
            results = {
                'filename': filename,
                'file_size': file_size,
                'file_type': file_type,
                'upload_time': datetime.now().isoformat(),
                'analysis': {
                    'mime_type': file.content_type,
                    'hash': hashlib.md5(open(filepath, 'rb').read()).hexdigest()
                }
            }
            
            # Save to history
            with sqlite3.connect('forensics.db') as conn:
                c = conn.cursor()
                c.execute(
                    'INSERT INTO analysis_history (type, target, result) VALUES (?, ?, ?)',
                    ('file', filename, json.dumps(results))
                )
                conn.commit()
            
            # Add visualizations
            visualizations = {}
            
            # Byte frequency visualization
            if 'byte_frequency' in results.get('content_analysis', {}):
                freq_data = results['content_analysis']['byte_frequency']
                fig = go.Figure(data=[go.Bar(
                    x=list(range(256)),
                    y=freq_data,
                    marker_color='#6366f1'
                )])
                fig.update_layout(
                    title='Byte Frequency Distribution',
                    xaxis_title='Byte Value',
                    yaxis_title='Frequency',
                    font={'color': "#1e293b"},
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    height=400
                )
                visualizations['byte_frequency'] = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)
            
            # Security score gauge
            if 'security_score' in results:
                gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=results['security_score'],
                    domain={'x': [0, 1], 'y': [0, 1]},
                    title={'text': "Security Score"},
                    gauge={
                        'axis': {'range': [0, 100]},
                        'bar': {'color': "#6366f1"},
                        'steps': [
                            {'range': [0, 40], 'color': "#ef4444"},
                            {'range': [40, 70], 'color': "#f59e0b"},
                            {'range': [70, 100], 'color': "#22c55e"}
                        ]
                    }
                ))
                gauge.update_layout(
                    font={'color': "#1e293b"},
                    paper_bgcolor="rgba(0,0,0,0)",
                    height=300
                )
                visualizations['security_gauge'] = json.dumps(gauge, cls=plotly.utils.PlotlyJSONEncoder)
            
            results['visualizations'] = visualizations
            
            # Generate report ID
            report_id = hashlib.md5(file.filename.encode()).hexdigest()
            results['report_id'] = report_id
            
            return jsonify({
                'success': True,
                'data': results
            })
            
        finally:
            # Clean up
            if os.path.exists(filepath):
                os.remove(filepath)
                
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Error analyzing file: {str(e)}'
        }), 500

@app.route('/analyze-url', methods=['POST'])
def analyze_url():
    try:
        app.logger.info('Starting URL analysis')
        url = request.form.get('url')
        if not url:
            return jsonify({
                'success': False,
                'error': 'No URL provided'
            }), 400

        # Analyze URL
        analyzer = URLAnalyzer()
        app.logger.info(f'Analyzing URL: {url}')
        results = analyzer.analyze_url(url)
        app.logger.info(f'Analysis results: {results}')
        
        if not results.get('success', False):
            return jsonify({
                'success': False,
                'error': results.get('error', 'Unknown error'),
                'data': results.get('data', {}),
                'issues': results.get('issues', [])
            }), 400
        
        # Save to history
        with sqlite3.connect('forensics.db') as conn:
            c = conn.cursor()
            c.execute(
                'INSERT INTO analysis_history (type, target, result) VALUES (?, ?, ?)',
                ('url', url, json.dumps(results['data']))
            )
            conn.commit()
        
        # Add visualizations
        visualizations = {}
        
        # Security score visualization
        security_info = results['data']['security_info']
        security_score = 0
        if security_info.get('https', False): security_score += 20
        if security_info.get('hsts', False): security_score += 20
        if security_info.get('xss_protection', False): security_score += 20
        if security_info.get('content_security', False): security_score += 20
        if security_info.get('frame_options', False): security_score += 20
        
        visualizations['security_gauge'] = {
            'data': [{
                'type': 'indicator',
                'mode': 'gauge+number',
                'value': security_score,
                'title': {'text': 'Security Score'},
                'gauge': {
                    'axis': {'range': [0, 100]},
                    'bar': {'color': '#6366f1'},
                    'steps': [
                        {'range': [0, 20], 'color': '#ef4444'},
                        {'range': [20, 40], 'color': '#f59e0b'},
                        {'range': [40, 60], 'color': '#fbbf24'},
                        {'range': [60, 80], 'color': '#84cc16'},
                        {'range': [80, 100], 'color': '#22c55e'}
                    ]
                }
            }],
            'layout': {
                'height': 300,
                'margin': {'t': 25, 'b': 0, 'l': 25, 'r': 25}
            }
        }
        
        # Add visualizations to results
        results['data']['visualizations'] = visualizations
        
        return jsonify(results)
        
    except Exception as e:
        app.logger.error(f'URL analysis error: {str(e)}')
        return jsonify({
            'success': False,
            'error': 'Internal server error'
        }), 500
        
        # Add visualizations
        visualizations = {}
        
        # Security Score Gauge
        if 'security_score' in results:
            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=results['security_score'],
                domain={'x': [0, 1], 'y': [0, 1]},
                title={'text': "Security Score"},
                gauge={
                    'axis': {'range': [0, 100]},
                    'bar': {'color': "#6366f1"},
                    'steps': [
                        {'range': [0, 40], 'color': "#ef4444"},
                        {'range': [40, 70], 'color': "#f59e0b"},
                        {'range': [70, 100], 'color': "#22c55e"}
                    ]
                }
            ))
            gauge.update_layout(
                font={'color': "#1e293b"},
                paper_bgcolor="rgba(0,0,0,0)",
                height=300
            )
            visualizations['security_gauge'] = json.dumps(gauge, cls=plotly.utils.PlotlyJSONEncoder)
        
        # Headers Analysis
        if 'headers_analysis' in results and 'missing_headers' in results['headers_analysis']:
            missing = len(results['headers_analysis']['missing_headers'])
            present = 4 - missing  # Total important headers we check
            
            pie = go.Figure(data=[go.Pie(
                labels=['Present', 'Missing'],
                values=[present, missing],
                hole=.3,
                marker={'colors': ['#22c55e', '#ef4444']}
            )])
            pie.update_layout(
                title='Security Headers',
                font={'color': "#1e293b"},
                paper_bgcolor="rgba(0,0,0,0)",
                height=300
            )
            visualizations['headers_analysis'] = json.dumps(pie, cls=plotly.utils.PlotlyJSONEncoder)
        
        results['visualizations'] = visualizations
        
        # Generate report ID
        report_id = hashlib.md5(url.encode()).hexdigest()
        results['report_id'] = report_id
        
        return jsonify({
            'success': True,
            'data': results
        })
    
    except requests.exceptions.RequestException as e:
        return jsonify({
            'success': False,
            'error': f'Failed to connect to the URL: {str(e)}'
        }), 500
    except Exception as e:
        app.logger.error(f'Error in analyze_url: {str(e)}')
        app.logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': f'Error analyzing URL: {str(e)}',
            'data': {},
            'issues': [f'Server error: {str(e)}']
        }), 500

@app.route("/report")
def report():
    path = request.args.get('path')
    if not path or not os.path.exists(path):
        raise NotFound("Report not found.")
    folder, file_name = os.path.split(path)
    return send_from_directory(folder, file_name)

if __name__ == "__main__":
    app.run(debug=True)

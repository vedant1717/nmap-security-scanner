import os
import csv
import uuid
import io
import threading
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from scanner import scan_ip

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.secret_key = 'super_secret_session_key_12345'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # If AJAX request
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or '/api/' in request.path:
                return jsonify({'error': 'Unauthorized'}), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Store scan results in memory for simplicity 
scan_jobs = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Secured password hash derived using pbkdf2/scrypt 
        secure_hash = "scrypt:32768:8:1$ySmtejLmidfsh4NC$8e850f3c9086f327e5ad1aaaf8c78ad3a825614aed2067173135129635abf431d96904e2fc8659feb6f80ce24091828cae90cdd79a8cd6cb735b5123beb960df"
        if username == 'vedantpatil' and check_password_hash(secure_hash, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
@login_required
def upload_csv():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and file.filename.endswith('.csv'):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        targets = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Expecting columns 'IP' and 'Port' (case insensitive)
                    ip_col = next((k for k in row.keys() if 'ip' in k.lower()), None)
                    port_col = next((k for k in row.keys() if 'port' in k.lower()), None)
                    if ip_col and port_col:
                        targets.append({'ip': row[ip_col].strip(), 'port': row[port_col].strip()})
        except Exception as e:
            return jsonify({'error': f"Failed to parse CSV: {str(e)}"}), 400
            
        if not targets:
            return jsonify({'error': 'Could not find "IP" and "Port" columns in CSV.'}), 400
            
        job_id = str(uuid.uuid4())
        scan_jobs[job_id] = {
            'status': 'running',
            'total': len(targets),
            'completed': 0,
            'results': []
        }
        
        # Start background thread
        thread = threading.Thread(target=process_scans, args=(job_id, targets))
        thread.start()
        
        return jsonify({'job_id': job_id, 'message': 'Scan started successfully'})
        
    return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400

def process_scans(job_id, targets):
    job = scan_jobs[job_id]
    for target in targets:
        ip = target['ip']
        port = target['port']
        
        # Run scan
        result = scan_ip(ip, port)
        
        job['results'].append({
            'ip': ip,
            'port': port,
            'service': result['service'],
            'version': result['version'],
            'findings': '; '.join(result['findings']) if result['findings'] else 'No issues found',
            'raw_output': result['raw_output'],
            'command': result['command']
        })
        job['completed'] += 1
        
    job['status'] = 'completed'

@app.route('/api/status/<job_id>', methods=['GET'])
@login_required
def get_status(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
        
    return jsonify({
        'status': job['status'],
        'total': job['total'],
        'completed': job['completed'],
        'results': job['results']
    })

@app.route('/api/download/<job_id>', methods=['GET'])
@login_required
def download_report(job_id):
    job = scan_jobs.get(job_id)
    if not job or job['status'] != 'completed':
        return jsonify({'error': 'Job not ready or not found'}), 404
        
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['IP', 'Port', 'Service', 'Version', 'Findings'])
    
    for res in job['results']:
        writer.writerow([res['ip'], res['port'], res['service'], res['version'], res['findings']])
        
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='nmap_scan_report.csv'
    )

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

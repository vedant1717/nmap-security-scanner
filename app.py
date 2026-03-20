import os
import csv
import uuid
import io
import threading
from functools import wraps
from flask import Flask, request, jsonify, render_template, send_file, session, redirect, url_for, flash
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from scanner import scan_ip, scan_all_ports, scan_ip_accessibility

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
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/service')
@login_required
def service_scan_page():
    return render_template('index.html')

@app.route('/ports')
@login_required
def port_scan_page():
    return render_template('port_scan.html')

@app.route('/ip_scan')
@login_required
def ip_scan_page():
    return render_template('ip_scan.html')

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
    import time
    job = scan_jobs[job_id]
    for target in targets:
        # Check for pause
        while job['status'] == 'paused':
            time.sleep(1)
            
        # Check for abort
        if job['status'] == 'aborted':
            break
            
        ip = target['ip']
        port = target['port']
        job['current_target'] = f"{ip}:{port}"
        
        while True:
            job['current_target_start_time'] = time.time()
            result = scan_ip(ip, port, job=job)
            
            if job.get('restarted'):
                job['restarted'] = False
                continue
                
            if result is None:
                break
            
            job['results'].append({
                'ip': ip,
                'port': port,
                'service': result['service'],
                'version': result['version'],
                'findings': '\n'.join(result['findings']) if result['findings'] else 'No issues found',
                'recommendation': result.get('recommendation', 'N/A'),
                'raw_output': result['raw_output'],
                'command': result['command']
            })
            job['completed'] += 1
            break
        
    if job['status'] != 'aborted':
        job['status'] = 'completed'

@app.route('/api/upload_ports', methods=['POST'])
@login_required
def upload_ports_csv():
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
                    ip_col = next((k for k in row.keys() if 'ip' in k.lower()), None)
                    if ip_col:
                        targets.append({'ip': row[ip_col].strip()})
        except Exception as e:
            return jsonify({'error': f"Failed to parse CSV: {str(e)}"}), 400
            
        if not targets:
            return jsonify({'error': 'Could not find "IP" column in CSV.'}), 400
            
        timing = request.form.get('timing', 'None')
        ports = request.form.get('ports', '')
            
        job_id = str(uuid.uuid4())
        scan_jobs[job_id] = {
            'type': 'port',
            'status': 'running',
            'total': len(targets),
            'completed': 0,
            'results': [],
            'timing': timing,
            'ports': ports
        }
        
        thread = threading.Thread(target=process_port_scans, args=(job_id, targets))
        thread.start()
        
        return jsonify({'job_id': job_id, 'message': 'Port scan started successfully'})
        
    return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400

def process_port_scans(job_id, targets):
    import time
    job = scan_jobs[job_id]
    for target in targets:
        while job['status'] == 'paused':
            time.sleep(1)
            
        if job['status'] == 'aborted':
            break
            
        ip = target['ip']
        job['current_target'] = ip
        
        while True:
            job['current_target_start_time'] = time.time()
            result = scan_all_ports(ip, job=job)
            
            if job.get('restarted'):
                job['restarted'] = False
                continue
                
            if result is None:
                break
                
            job['results'].append({
                'ip': ip,
                'open_ports': result['open_ports'],
                'raw_output': result['raw_output'],
                'command': result['command']
            })
            job['completed'] += 1
            break
        
    if job['status'] != 'aborted':
        job['status'] = 'completed'

@app.route('/api/upload_ip', methods=['POST'])
@login_required
def upload_ip_csv():
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
                    ip_col = next((k for k in row.keys() if 'ip' in k.lower()), None)
                    if ip_col:
                        targets.append({'ip': row[ip_col].strip()})
        except Exception as e:
            return jsonify({'error': f"Failed to parse CSV: {str(e)}"}), 400
            
        if not targets:
            return jsonify({'error': 'Could not find "IP" column in CSV.'}), 400
            
        job_id = str(uuid.uuid4())
        scan_jobs[job_id] = {
            'type': 'ip',
            'status': 'running',
            'total': len(targets),
            'completed': 0,
            'results': []
        }
        
        thread = threading.Thread(target=process_ip_scans, args=(job_id, targets))
        thread.start()
        
        return jsonify({'job_id': job_id, 'message': 'IP Accessibility scan started successfully'})
        
    return jsonify({'error': 'Invalid file format. Please upload a CSV file.'}), 400

def process_ip_scans(job_id, targets):
    import time
    job = scan_jobs[job_id]
    for target in targets:
        while job['status'] == 'paused':
            time.sleep(1)
            
        if job['status'] == 'aborted':
            break
            
        ip = target['ip']
        job['current_target'] = ip
        
        while True:
            job['current_target_start_time'] = time.time()
            result = scan_ip_accessibility(ip, job=job)
            
            if job.get('restarted'):
                job['restarted'] = False
                continue
                
            if result is None:
                break
                
            job['results'].append({
                'ip': ip,
                'accessibility': result['accessibility'],
                'raw_output': result['raw_output'],
                'command': result['command']
            })
            job['completed'] += 1
            break
        
    if job['status'] != 'aborted':
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

@app.route('/api/action/<job_id>', methods=['POST'])
@login_required
def job_action(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
        
    action = request.json.get('action')
    if action not in ['pause', 'resume', 'abort', 'skip', 'restart']:
        return jsonify({'error': 'Invalid action parameter'}), 400
        
    if job['status'] in ['completed', 'aborted']:
        return jsonify({'error': 'Job already finished or aborted'}), 400
        
    if action == 'pause':
        job['status'] = 'paused'
    elif action == 'resume':
        job['status'] = 'running'
    elif action == 'abort':
        job['status'] = 'aborted'
    elif action == 'skip':
        job['skip_current'] = True
    elif action == 'restart':
        job['restart_current'] = True
        
    return jsonify({'message': f'Job {action} triggered successfully'})

@app.route('/api/troubleshoot/<job_id>', methods=['GET'])
@login_required
def troubleshoot(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
        
    if job['status'] in ['completed', 'aborted', 'paused']:
        return jsonify({'status': 'idle', 'message': f'Scan is currently {job["status"]}.'})
        
    target = job.get('current_target', 'Pending')
    start_time = job.get('current_target_start_time')
    
    if not start_time:
        return jsonify({'status': 'idle', 'message': 'Initializing targets...'})
        
    elapsed = int(time.time() - start_time)
    
    reason = "Target is responding normally."
    if elapsed > 180:
        reason = "CRITICAL: Scan exceedingly slow. The firewall is likely stealth-dropping probes (filtered ports), or aggressive rate-limiting is occurring."
    elif elapsed > 60:
        reason = "WARNING: Scan taking longer than usual. The host might be rate-limiting requests or has a high latency connection."
        
    return jsonify({
        'status': 'active',
        'current_target': target,
        'elapsed_seconds': elapsed,
        'likely_reason': reason
    })

@app.route('/api/live/<job_id>', methods=['GET'])
@login_required
def get_live_output(job_id):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({'output': 'Job not found.'})
        
    return jsonify({'output': job.get('live_output', 'Waiting for NMAP to initialize (Execution allocating)...')})

@app.route('/api/download/<job_id>', methods=['GET'])
@login_required
def download_report(job_id):
    job = scan_jobs.get(job_id)
    if not job or job['status'] != 'completed':
        return jsonify({'error': 'Job not ready or not found'}), 404
        
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['IP', 'Port', 'Service', 'Version', 'Findings', 'Recommendation'])
    
    for res in job['results']:
        writer.writerow([res['ip'], res['port'], res['service'], res['version'], res['findings'], res['recommendation']])
        
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='nmap_scan_report.csv'
    )

@app.route('/api/download_ports/<job_id>', methods=['GET'])
@login_required
def download_ports_report(job_id):
    job = scan_jobs.get(job_id)
    if not job or job['status'] != 'completed':
        return jsonify({'error': 'Job not ready or not found'}), 404
        
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['IP', 'Open Ports'])
    
    for res in job['results']:
        writer.writerow([res['ip'], res['open_ports']])
        
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='open_ports_report.csv'
    )

@app.route('/api/download_ip/<job_id>', methods=['GET'])
@login_required
def download_ip_report(job_id):
    job = scan_jobs.get(job_id)
    if not job or job['status'] != 'completed':
        return jsonify({'error': 'Job not ready or not found'}), 404
        
    si = io.StringIO()
    writer = csv.writer(si)
    writer.writerow(['IP', 'Accessibility'])
    
    for res in job['results']:
        writer.writerow([res['ip'], res['accessibility']])
        
    output = io.BytesIO()
    output.write(si.getvalue().encode('utf-8'))
    output.seek(0)
    
    return send_file(
        output,
        mimetype='text/csv',
        as_attachment=True,
        download_name='ip_accessibility_report.csv'
    )

import html as html_lib
import re

@app.route('/api/download_raw/<job_id>/<ip>/<port>', methods=['GET'])
@login_required
def download_raw(job_id, ip, port):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
        
    for res in job['results']:
        if res['ip'] == ip and res['port'] == port:
            raw_output = res['raw_output']
            findings = res['findings']
            
            # HTML escape the output to prevent injection and format
            escaped_output = html_lib.escape(raw_output)
            raw_lines = escaped_output.split('\n')
            
            unwanted_prefixes = (
                'Stats:',
                'Starting Nmap',
                'Nmap done:',
                'Initiating',
                'Completed',
                'NSE:',
                'Read data files from:',
                'Service detection performed'
            )
            
            lines = []
            for line in raw_lines:
                if line.strip().startswith(unwanted_prefixes):
                    continue
                lines.append(line)
            
            bad_keywords = ['TLSv1.0', 'TLSv1.1']
            if 'Expired' in findings:
                bad_keywords.append('Not valid after:')
            if 'Self-signed' in findings or 'non-trusted' in findings:
                bad_keywords.extend(['Issuer:', 'Subject:'])
            
            # Dynamically pull specific weak ciphers from the finding log
            findings_ciphers = re.findall(r'TLS_[A-Z0-9_]+WITH[A-Z0-9_]+', findings)
            bad_keywords.extend(findings_ciphers)
            
            target_version = res.get('version', '')
            # Enforce that versions must contain numbers to warrant explicit Red Highlighting
            has_digit = bool(re.search(r'\d', target_version)) if target_version else False
            
            highlighted_lines = []
            for line in lines:
                is_bad = False
                for kw in bad_keywords:
                    if kw in line:
                        is_bad = True
                        break
                        
                # Version Disclosure Strict Regex Matching
                if not is_bad and target_version and target_version not in ['Unknown', 'N/A'] and has_digit:
                    if target_version in line and re.match(r'^\d+/(tcp|udp)\s+open', line):
                        is_bad = True
                
                if is_bad:
                    highlighted_lines.append(f'<span style="color: #ff5555; font-weight: bold;">{line}</span>')
                else:
                    highlighted_lines.append(line)
                    
            final_html = f"""<!DOCTYPE html>
<html>
<head>
<title>NMAP Output - {ip}:{port}</title>
<style>
body {{ background-color: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; line-height: 1.4; }}
</style>
</head>
<body>
<h2>NMAP Scan Result for {ip}:{port}</h2>
<p style="color:#8b949e; font-size: 0.9em;">Command: {html_lib.escape(res['command'])}</p>
<hr style="border:1px solid #30363d; margin-bottom:20px;">
<pre>
{chr(10).join(highlighted_lines)}
</pre>
</body>
</html>"""
            
            output_io = io.BytesIO()
            output_io.write(final_html.encode('utf-8'))
            output_io.seek(0)
            
            return send_file(
                output_io,
                mimetype='text/html',
                as_attachment=True,
                download_name=f'nmap_output_{ip}_{port}.html'
            )
            
    return jsonify({'error': 'Result not found for the specified Target'}), 404

@app.route('/api/download_target_raw/<job_id>/<ip>', methods=['GET'])
@login_required
def download_target_raw(job_id, ip):
    job = scan_jobs.get(job_id)
    if not job:
        return jsonify({'error': 'Job not found'}), 404
        
    for res in job['results']:
        if res['ip'] == ip:
            raw_output = res['raw_output']
            escaped_output = html_lib.escape(raw_output)
            
            final_html = f"""<!DOCTYPE html>
<html>
<head>
<title>NMAP Scan - {ip}</title>
<style>
body {{ background-color: #0d1117; color: #c9d1d9; font-family: monospace; padding: 20px; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; line-height: 1.4; }}
</style>
</head>
<body>
<h2>NMAP Scan Result for {ip}</h2>
<p style="color:#8b949e; font-size: 0.9em;">Command: {html_lib.escape(res['command'])}</p>
<hr style="border:1px solid #30363d; margin-bottom:20px;">
<pre>
{escaped_output}
</pre>
</body>
</html>"""
            
            output_io = io.BytesIO()
            output_io.write(final_html.encode('utf-8'))
            output_io.seek(0)
            
            return send_file(
                output_io,
                mimetype='text/html',
                as_attachment=True,
                download_name=f'nmap_targetscan_{ip}.html'
            )
            
    return jsonify({'error': 'Result not found'}), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)

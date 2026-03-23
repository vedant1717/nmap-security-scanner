import subprocess
import re
import time
import requests
import os
import uuid
import threading
from datetime import datetime

CIPHER_CACHE = {}

def get_cipher_security(cipher):
    if cipher in CIPHER_CACHE:
        return CIPHER_CACHE[cipher]
        
    try:
        url = f"https://ciphersuite.info/api/cs/{cipher}/"
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if cipher in data:
                security = data[cipher].get('security', 'unknown')
                CIPHER_CACHE[cipher] = security
                return security
    except Exception:
        pass
        
    CIPHER_CACHE[cipher] = 'unknown'
    return 'unknown'

def generate_recommendations(findings, version="Unknown", secure_ciphers=None):
    if not findings or findings == ['Port closed or host down']:
        return "It is recommended to verify if the service is intended to be accessible."
    
    recs = []
    findings_str = " ".join(findings).lower()
    
    if 'expired' in findings_str:
        recs.append("renew the SSL certificate immediately")
    if 'untrusted' in findings_str or 'self-signed' in findings_str:
        recs.append("install a certificate from a trusted public Certificate Authority")
    if 'tlsv1.0' in findings_str or 'tlsv1.1' in findings_str or 'outdated' in findings_str:
        recs.append("disable outdated TLS 1.0/1.1 protocols and mandate TLS 1.2 or higher")
    if 'weak' in findings_str or 'insecure' in findings_str or 'deprecated' in findings_str:
        if secure_ciphers:
            recs.append(f"disable the identified weak/insecure ciphers and configure the server to prioritize your secure suites such as {', '.join(secure_ciphers)}")
        else:
            recs.append("disable the identified weak/insecure ciphers and upgrade to standard securely recommended ciphers (e.g., TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256)")
    
    if version and version != 'Unknown' and version != 'N/A':
        recs.append("obscure software version banners to prevent fingerprinting by attackers")
        
    if recs:
        return "It is recommended to " + ", and to ".join(recs) + "."
    return "It is recommended to maintain the current secure configuration."

def scan_ip(ip, port, job=None):
    sanitized_port = re.sub(r'[^0-9,\-]', '', str(port))
    sanitized_port = re.sub(r',+', ',', sanitized_port).strip(',')
    if not sanitized_port:
        sanitized_port = "1-65535"
        
    cmd = ["nmap", "-sV", "-Pn", "--script", "ssl-cert,ssl-enum-ciphers", "-p", sanitized_port, "--stats-every", "3s", ip]
    command_str = " ".join(cmd)
    
    try:
        # Running nmap command with dynamic polling against job status
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_buffer = []
        if job is not None:
            job['current_process'] = process
            job['live_output'] = ''
            
        def reader():
            for line in process.stdout:
                output_buffer.append(line)
                if job is not None:
                    job['live_output'] += line
                    
        reader_thread = threading.Thread(target=reader)
        reader_thread.daemon = True
        reader_thread.start()
            
        while process.poll() is None:
            if job is not None:
                if job.get('status') == 'aborted':
                    process.kill()
                    return {
                        'service': 'Aborted',
                        'version': 'N/A',
                        'findings': ['Scan aborted by user'],
                        'recommendation': 'N/A',
                        'raw_output': 'Process deliberately killed mid-scan.',
                        'command': command_str
                    }
                if job.get('skip_current'):
                    process.kill()
                    job['skip_current'] = False
                    return {
                        'service': 'Skipped',
                        'version': 'N/A',
                        'findings': ['Manually skipped by user'],
                        'recommendation': 'N/A',
                        'raw_output': 'Scan skipped per user request.',
                        'command': command_str
                    }
                if job.get('restart_current'):
                    process.kill()
                    job['restart_current'] = False
                    job['restarted'] = True
                    return None
            time.sleep(0.5)
            
        reader_thread.join()
        output = "".join(output_buffer)
        
        # Check if host is down or port is filtered/closed
        if "Host seems down" in output or f"{port}/tcp closed" in output or f"{port}/tcp filtered" in output:
            return {
                'service': 'N/A',
                'version': 'N/A',
                'findings': ['Port closed or host down'],
                'recommendation': 'It is recommended to verify if the service is accessible.',
                'raw_output': output,
                'command': command_str
            }
            
        # Parse NMAP output
        service, version, findings, secure_ciphers = parse_output(output)
        recommendation = generate_recommendations(findings, version, secure_ciphers)
        
        # Format the output dict
        return {
            'service': service or 'Unknown',
            'version': version or 'Unknown',
            'findings': findings,
            'recommendation': recommendation,
            'raw_output': output,
            'command': command_str
        }
            
    except Exception as e:
        return {
            'service': 'Error',
            'version': 'N/A',
            'findings': [f"Execution error: {str(e)}"],
            'recommendation': 'N/A',
            'raw_output': '',
            'command': command_str
        }

def parse_output(output):
    findings = []
    current_date = datetime.now()
    
    # 1. Service and Version disclosure
    # Matches lines like: 443/tcp open  https   nginx 1.18.0
    service_match = re.search(r'^\d+/tcp\s+open\s+([\w\-\/\.]+)\s*(.*)$', output, re.MULTILINE)
    service = ""
    version = ""
    if service_match:
        service = service_match.group(1).strip()
        version_part = service_match.group(2).strip()
        if version_part:
            # We matched something beyond the service name
            if not version_part.startswith('|') and not version_part.startswith('_'):
                version = version_part

    # 2. Extract Certificate Expiry and Issuer
    not_after_match = re.search(r'Not valid after:\s*([0-9T:-]+)', output)
    if not_after_match:
        not_after_str = not_after_match.group(1)
        try:
            # e.g., 2024-01-01T00:00:00
            cert_expiry = datetime.fromisoformat(not_after_str.replace('Z', '+00:00'))
            if cert_expiry.timestamp() < current_date.timestamp():
                findings.append(f"CRITICAL: Certificate Expired on {not_after_str.split('T')[0]}")
        except:
            findings.append("Could not parse certificate expiry limit.")

    issuer_match = re.search(r'Issuer:\s*([^\n]+)', output)
    subject_match = re.search(r'Subject:\s*([^\n]+)', output)
    
    if issuer_match and subject_match:
        issuer = issuer_match.group(1)
        subject = subject_match.group(1)
        
        # Basic check for self-signed
        if issuer == subject:
            findings.append("WARNING: Self-signed certificate detected")
        else:
            trusted_keywords = ['DigiCert', "Let's Encrypt", 'GlobalSign', 'Sectigo', 'GoDaddy', 'Google Trust', 'Amazon', 'Cloudflare', 'IdenTrust', 'Entrust', 'Digi-Cert']
            is_trusted = any(keyword.lower() in issuer.lower() for keyword in trusted_keywords)
            if not is_trusted:
                extracted_issuer = issuer.split('commonName=')[-1].split('/')[0] if 'commonName=' in issuer else issuer[:50]
                findings.append(f"INFO: Certificate issuer may be non-trusted ({extracted_issuer})")

    # 3. Old TLS versions
    if "TLSv1.0:" in output:
        findings.append("CRITICAL: TLSv1.0 is enabled (Outdated/Insecure)")
    if "TLSv1.1:" in output:
        findings.append("CRITICAL: TLSv1.1 is enabled (Outdated/Insecure)")
        
    # 4. Cipher evaluation via Ciphersuite.info API
    weak_ciphers = []
    insecure_ciphers = []
    secure_ciphers = []
    
    # Extract all TLS ciphers
    cipher_matches = re.findall(r'(TLS_[A-Z0-9_]+WITH[A-Z0-9_]+)', output)
    unique_ciphers = list(set(cipher_matches))
    
    for cipher in unique_ciphers:
        security = get_cipher_security(cipher)
        if security == 'insecure':
            insecure_ciphers.append(cipher)
        elif security == 'weak':
            weak_ciphers.append(cipher)
        elif security in ['secure', 'recommended']:
            secure_ciphers.append(cipher)
            
    if weak_ciphers:
        findings.append(f"WARNING: Weak ciphers detected via Ciphersuite.info: {', '.join(weak_ciphers)}")
    if insecure_ciphers:
        findings.append(f"CRITICAL: Insecure/Deprecated ciphers detected via Ciphersuite.info: {', '.join(insecure_ciphers)}")
        
    return service, version, findings, secure_ciphers

def scan_all_ports(ip, job=None):
    cmd = ["nmap", "-Pn", "--open", "--stats-every", "3s"]
    
    port_arg = "-p-"
    if job and job.get('ports'):
        sanitized_ports = re.sub(r'[^0-9,\-]', '', job['ports'])
        sanitized_ports = re.sub(r',+', ',', sanitized_ports).strip(',')
        if sanitized_ports:
            port_arg = f"-p{sanitized_ports}"
            
    cmd.append(port_arg)
    
    if job and job.get('timing') and job['timing'] in ['T1', 'T2', 'T3', 'T4', 'T5']:
        cmd.append(f"-{job['timing']}")
        
    cmd.append(ip)
    command_str = " ".join(cmd)
        
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_buffer = []
        if job is not None:
            job['current_process'] = process
            job['live_output'] = ''
            
        def reader():
            for line in process.stdout:
                output_buffer.append(line)
                if job is not None:
                    job['live_output'] += line
                    
        reader_thread = threading.Thread(target=reader)
        reader_thread.daemon = True
        reader_thread.start()
            
        while process.poll() is None:
            if job is not None and job.get('status') == 'aborted':
                process.kill()
                return {
                    'open_ports': 'Scan aborted by user',
                    'raw_output': 'Process deliberately killed mid-scan.',
                    'command': command_str
                }
            if job is not None and job.get('skip_current'):
                process.kill()
                job['skip_current'] = False
                return {
                    'open_ports': 'Skipped',
                    'raw_output': 'Scan skipped.',
                    'command': command_str
                }
            if job is not None and job.get('restart_current'):
                process.kill()
                job['restart_current'] = False
                job['restarted'] = True
                return None
            time.sleep(0.5)
            
        reader_thread.join()
        output = "".join(output_buffer)
        
        if "Host seems down" in output:
            return {
                'open_ports': 'Host down',
                'raw_output': output,
                'command': command_str
            }
            
        open_ports = []
        lines = output.split('\n')
        for line in lines:
            match = re.match(r'^(\d+)/tcp\s+open\s+', line)
            if match:
                open_ports.append(match.group(1))
                
        open_ports_str = ", ".join(open_ports) if open_ports else "No open ports found"
        
        return {
            'open_ports': open_ports_str,
            'raw_output': output,
            'command': command_str
        }
    except Exception as e:
        return {
            'open_ports': f"Error: {str(e)}",
            'raw_output': '',
            'command': command_str
        }

def scan_ip_accessibility(ip, job=None):
    cmd = ["nmap", "-sn", "-n", "--stats-every", "3s", ip]
    command_str = " ".join(cmd)
        
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        output_buffer = []
        if job is not None:
            job['current_process'] = process
            job['live_output'] = ''
            
        def reader():
            for line in process.stdout:
                output_buffer.append(line)
                if job is not None:
                    job['live_output'] += line
                    
        reader_thread = threading.Thread(target=reader)
        reader_thread.daemon = True
        reader_thread.start()
            
        while process.poll() is None:
            if job is not None and job.get('status') == 'aborted':
                process.kill()
                return {
                    'accessibility': 'Scan aborted by user',
                    'raw_output': 'Process deliberately killed mid-scan.',
                    'command': command_str
                }
            if job is not None and job.get('skip_current'):
                process.kill()
                job['skip_current'] = False
                return {
                    'accessibility': 'Skipped',
                    'raw_output': 'Scan skipped.',
                    'command': command_str
                }
            if job is not None and job.get('restart_current'):
                process.kill()
                job['restart_current'] = False
                job['restarted'] = True
                return None
            time.sleep(0.5)
            
        reader_thread.join()
        output = "".join(output_buffer)
        
        if "Host is up" in output:
            accessibility = "Accessible"
        elif "Host seems down" in output:
            accessibility = "Not Accessible"
        else:
            accessibility = "Not Accessible (Blocked)"
            
        return {
            'accessibility': accessibility,
            'raw_output': output,
            'command': command_str
        }
    except Exception as e:
        return {
            'accessibility': f"Error: {str(e)}",
            'raw_output': '',
            'command': command_str
        }

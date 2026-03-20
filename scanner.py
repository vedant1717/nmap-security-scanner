import subprocess
import re
from datetime import datetime

def scan_ip(ip, port):
    cmd = ["nmap", "-sV", "--script", "ssl-cert,ssl-enum-ciphers", "-p", str(port), ip]
    command_str = " ".join(cmd)
    
    try:
        # Running nmap command
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        output = result.stdout
        error = result.stderr
        
        # Check if host is down or port is filtered/closed
        if "Host seems down" in output or f"{port}/tcp closed" in output or f"{port}/tcp filtered" in output:
            return {
                'service': 'N/A',
                'version': 'N/A',
                'findings': ['Port closed or host down'],
                'raw_output': output,
                'command': command_str
            }
            
        # Parse NMAP output
        service, version, findings = parse_output(output)
        
        # Format the output dict
        return {
            'service': service or 'Unknown',
            'version': version or 'Unknown',
            'findings': findings,
            'raw_output': output,
            'command': command_str
        }
            
    except subprocess.TimeoutExpired:
        return {
            'service': 'Timeout',
            'version': 'N/A',
            'findings': ['Scan timed out after 180 seconds'],
            'raw_output': 'Process timed out.',
            'command': command_str
        }
    except Exception as e:
        return {
            'service': 'Error',
            'version': 'N/A',
            'findings': [f"Execution error: {str(e)}"],
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
                findings.append(f"Service version disclosed: {service} {version}")

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
        
    # 4. Cipher evaluation (TLS 1.2 and 1.3)
    # Looking for lines like `TLS_RSA_WITH_AES_128_CBC_SHA (rsa 2048) - C`
    # or `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (secp256r1) - A`
    weak_ciphers = []
    deprecated_ciphers = []
    
    cipher_lines = re.findall(r'(\w+WITH\w+)\s+\([^\)]+\)\s+-\s+([A-F])', output)
    
    for cipher, grade in cipher_lines:
        if grade in ['F']:
            deprecated_ciphers.append(cipher)
        elif grade in ['C', 'D', 'E']:
            weak_ciphers.append(cipher)
            
    # Deduplicate
    weak_ciphers = list(set(weak_ciphers))
    deprecated_ciphers = list(set(deprecated_ciphers))
    
    if weak_ciphers:
        findings.append(f"WARNING: Weak ciphers detected ({len(weak_ciphers)} ciphers like {weak_ciphers[0]})")
    if deprecated_ciphers:
        findings.append(f"CRITICAL: Deprecated ciphers detected ({len(deprecated_ciphers)} ciphers like {deprecated_ciphers[0]})")
        
    return service, version, findings

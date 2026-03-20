document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const browseBtn = document.getElementById('browse-btn');
    const uploadError = document.getElementById('upload-error');
    
    const uploadSection = document.getElementById('upload-section');
    const progressSection = document.getElementById('progress-section');
    const resultsSection = document.getElementById('results-section');
    
    const progressBar = document.getElementById('progress-bar-fill');
    const scanCount = document.getElementById('scan-count');
    const scanStatusText = document.getElementById('scan-status-text');
    
    const resultsBody = document.getElementById('results-body');
    const downloadBtn = document.getElementById('download-btn');
    
    const pauseBtn = document.getElementById('pause-btn');
    const resumeBtn = document.getElementById('resume-btn');
    const abortBtn = document.getElementById('abort-btn');
    const troubleshootBtn = document.getElementById('troubleshoot-btn');
    const scanActions = document.getElementById('scan-actions');
    
    const timingButtons = document.querySelectorAll('.timing-btn');
    const timingDesc = document.getElementById('timing-desc');
    let selectedTiming = 'None';
    
    const descriptions = {
        'None': 'No explicit timing flags applied. Standard reliable NMAP execution.',
        'T1': 'Sneaky (Slowest): Useful for IDS evasion. Leaves 15 seconds between active probes.',
        'T2': 'Polite (Slow): Reduces bandwidth. Leaves 0.4 seconds between active probes.',
        'T3': 'Normal (Default): Default operating speed dynamically adjusting to network latency.',
        'T4': 'Aggressive (Fast): Accelerates execution by bypassing slow ping evaluations. Assumes a highly reliable, fast network.',
        'T5': 'Insane (Extremely Fast): Sacrifices active accuracy for extreme speeds. May drop accurate port readings on lagging networks.'
    };

    if (timingButtons.length > 0) {
        timingButtons.forEach(btn => {
            btn.onclick = () => {
                timingButtons.forEach(b => {
                    b.style.background = '';
                    b.style.borderColor = '';
                    b.classList.remove('active');
                });
                btn.classList.add('active');
                btn.style.background = 'rgba(88, 166, 255, 0.2)';
                btn.style.borderColor = 'rgba(88, 166, 255, 0.5)';
                selectedTiming = btn.dataset.timing;
                timingDesc.textContent = descriptions[selectedTiming];
            };
        });
    }
    
    // Modal Elements
    const rawModal = document.getElementById('raw-modal');
    const closeModal = document.getElementById('close-modal');
    const modalCommand = document.getElementById('modal-command');
    const modalOutput = document.getElementById('modal-output');

    // Troubleshoot Elements
    const tsModal = document.getElementById('ts-modal');
    const closeTsModal = document.getElementById('close-ts-modal');
    const tsTarget = document.getElementById('ts-target');
    const tsElapsed = document.getElementById('ts-elapsed');
    const tsDiagnostic = document.getElementById('ts-diagnostic');
    const tsRestartBtn = document.getElementById('ts-restart-btn');
    let tsInterval = null;

    let currentJobId = null;
    let pollInterval = null;
    
    // Store results to view raw outputs later
    const scanDataStore = {};

    // Upload Handlers
    browseBtn.addEventListener('click', () => fileInput.click());
    
    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('dragover');
    });

    dropZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('dragover');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    function handleFile(file) {
        uploadError.classList.add('hidden');
        if (!file.name.toLowerCase().endsWith('.csv')) {
            showError("Please upload a CSV file.");
            return;
        }

        const customPorts = document.getElementById('custom-ports').value.trim();
        const formData = new FormData();
        formData.append('file', file);
        formData.append('timing', selectedTiming);
        formData.append('ports', customPorts);
        
        // Hide upload, show progress
        uploadSection.classList.add('hidden');
        progressSection.classList.remove('hidden');
        scanActions.classList.remove('hidden');
        pauseBtn.classList.remove('hidden');
        resumeBtn.classList.add('hidden');
        
        fetch('/api/upload_ports', {
            method: 'POST',
            body: formData
        })
        .then(res => res.json())
        .then(data => {
            if (data.error) {
                showUploadSection();
                showError(data.error);
            } else {
                currentJobId = data.job_id;
                startPolling();
            }
        })
        .catch(err => {
            showUploadSection();
            showError("Network error: Could not contact server.");
        });
    }

    function showUploadSection() {
        uploadSection.classList.remove('hidden');
        progressSection.classList.add('hidden');
        resultsSection.classList.add('hidden');
    }

    function showError(msg) {
        uploadError.textContent = msg;
        uploadError.classList.remove('hidden');
    }

    function startPolling() {
        if (pollInterval) clearInterval(pollInterval);
        resultsBody.innerHTML = '';
        resultsSection.classList.remove('hidden');
        
        pollInterval = setInterval(() => {
            fetch(`/api/status/${currentJobId}`)
                .then(res => res.json())
                .then(data => {
                    if (data.error) {
                        clearInterval(pollInterval);
                        return;
                    }
                    updateProgress(data);
                })
                .catch(err => console.error(err));
        }, 2000); // Poll every 2 seconds
    }

    function updateProgress(data) {
        const { total, completed, results, status } = data;
        
        scanCount.textContent = `${completed} / ${total}`;
        progressBar.style.width = `${total > 0 ? (completed / total) * 100 : 0}%`;
        
        if (status === 'completed' || status === 'aborted') {
            clearInterval(pollInterval);
            scanStatusText.textContent = status === 'completed' ? "Scan Completed!" : "Scan Aborted.";
            scanActions.classList.add('hidden');
            downloadBtn.classList.remove('hidden');
            downloadBtn.onclick = () => {
                window.location.href = `/api/download_ports/${currentJobId}`;
            };
            if(troubleshootBtn) troubleshootBtn.classList.add('hidden');
        } else if (status === 'paused') {
            scanStatusText.textContent = "Scan Paused";
            pauseBtn.classList.add('hidden');
            resumeBtn.classList.remove('hidden');
            if(troubleshootBtn) troubleshootBtn.classList.add('hidden');
        } else {
            scanStatusText.textContent = "Scanning...";
            pauseBtn.classList.remove('hidden');
            resumeBtn.classList.add('hidden');
            if(troubleshootBtn) troubleshootBtn.classList.remove('hidden');
        }
        
        // Render new results
        const currentRowsCount = resultsBody.children.length;
        if (results.length > currentRowsCount) {
            for (let i = currentRowsCount; i < results.length; i++) {
                const res = results[i];
                const key = `${res.ip}`;
                scanDataStore[key] = res; // Save for modal
                
                const tr = document.createElement('tr');
                
                // IP
                const targetTd = document.createElement('td');
                targetTd.innerHTML = `<strong>${res.ip}</strong>`;
                
                // Ports
                const portsTd = document.createElement('td');
                if(res.open_ports.includes('Error') || res.open_ports.includes('aborted') || res.open_ports.includes('down')) {
                    portsTd.innerHTML = `<span class="badge badge-warning">${res.open_ports}</span>`;
                } else if(res.open_ports.includes('No open ports')) {
                    portsTd.innerHTML = `<span class="badge badge-info">No open ports</span>`;
                } else {
                    // Split ports by comma and wrap in nice badges
                    const pList = res.open_ports.split(',').map(p => `<span class="badge badge-info" style="background: rgba(88,166,255,0.1); border-color: var(--accent-blue);">${p.trim()}</span>`).join(' ');
                    portsTd.innerHTML = `<div style="display:flex; flex-wrap:wrap; gap:5px;">${pList}</div>`;
                }
                
                // Action
                const actionTd = document.createElement('td');
                const viewBtn = document.createElement('button');
                viewBtn.className = 'btn-sm';
                viewBtn.textContent = 'View Modal';
                viewBtn.style.marginRight = '0.5rem';
                viewBtn.onclick = () => openModal(key);
                
                const dlBtn = document.createElement('button');
                dlBtn.className = 'btn-sm';
                dlBtn.textContent = 'Download Output (.html)';
                dlBtn.onclick = () => {
                    // We can reuse the same download_raw endpoint but supply a dummy port 'all' since we index it by ip in this job!
                    // Wait, our backend download_raw checks `if res['ip'] == ip and res['port'] == port:`
                    // Port scanning doesn't have `res['port']` strictly in the JSON object returned by api/status.
                    // So we must fix download_raw logic or just direct to a new /download_ports_raw endpoint!
                    window.location.href = `/api/download_ports_raw/${currentJobId}/${res.ip}`;
                };
                
                actionTd.appendChild(viewBtn);
                actionTd.appendChild(dlBtn);
                
                tr.appendChild(targetTd);
                tr.appendChild(portsTd);
                tr.appendChild(actionTd);
                
                resultsBody.appendChild(tr);
            }
        }
    }

    function openModal(key) {
        const data = scanDataStore[key];
        if (!data) return;
        modalCommand.textContent = data.command;
        modalOutput.textContent = data.raw_output || "No output captured.";
        rawModal.classList.remove('hidden');
    }

    closeModal.onclick = () => rawModal.classList.add('hidden');
    
    window.onclick = (e) => {
        if (e.target === rawModal) rawModal.classList.add('hidden');
        if (e.target === tsModal) {
            tsModal.classList.add('hidden');
            if (tsInterval) clearInterval(tsInterval);
        }
    }
        
    if (troubleshootBtn) {
        troubleshootBtn.onclick = () => {
            tsModal.classList.remove('hidden');
            pollTroubleshoot();
            tsInterval = setInterval(pollTroubleshoot, 1000);
        };
    }

    if (closeTsModal) {
        closeTsModal.onclick = () => {
            tsModal.classList.add('hidden');
            if (tsInterval) clearInterval(tsInterval);
        };
    }

    if (tsRestartBtn) {
        tsRestartBtn.onclick = () => {
            sendAction('restart');
            tsTarget.textContent = "Restarting...";
        };
    }

    function pollTroubleshoot() {
        if (!currentJobId) return;
        fetch(`/api/troubleshoot/${currentJobId}`)
            .then(res => res.json())
            .then(data => {
                if (data.status === 'active') {
                    tsTarget.textContent = data.current_target;
                    tsElapsed.textContent = data.elapsed_seconds;
                    
                    tsDiagnostic.textContent = data.likely_reason;
                    tsDiagnostic.className = 'badge';
                    
                    if (data.likely_reason.includes('CRITICAL')) {
                        tsDiagnostic.classList.add('badge-critical');
                    } else if (data.likely_reason.includes('WARNING')) {
                        tsDiagnostic.classList.add('badge-warning');
                    } else {
                        tsDiagnostic.classList.add('badge-info');
                        tsDiagnostic.style.background = 'rgba(88,166,255,0.1)';
                        tsDiagnostic.style.borderColor = 'var(--accent-blue)';
                    }
                } else {
                    tsTarget.textContent = data.message || data.status;
                }
            })
            .catch(err => console.error(err));
    }

    // Action Logic
    function sendAction(action) {
        if (!currentJobId) return;
        fetch(`/api/action/${currentJobId}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ action: action })
        }).catch(err => console.error(err));
    }

    pauseBtn.onclick = () => {
        sendAction('pause');
        pauseBtn.classList.add('hidden');
        resumeBtn.classList.remove('hidden');
        scanStatusText.textContent = "Pausing...";
    };

    resumeBtn.onclick = () => {
        sendAction('resume');
        resumeBtn.classList.add('hidden');
        pauseBtn.classList.remove('hidden');
        scanStatusText.textContent = "Resuming...";
    };

    abortBtn.onclick = () => {
        if (confirm("Are you sure you want to abort the scan?")) {
            sendAction('abort');
            scanActions.classList.add('hidden');
            scanStatusText.textContent = "Aborting...";
        }
    };
});

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
    const skipBtn = document.getElementById('skip-btn');
    const liveBtn = document.getElementById('live-btn');
    const troubleshootBtn = document.getElementById('troubleshoot-btn');
    const scanActions = document.getElementById('scan-actions');
    
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

    // Live CLI Elements
    const liveModal = document.getElementById('live-modal');
    const closeLiveModal = document.getElementById('close-live-modal');
    const liveOutput = document.getElementById('live-output');
    let liveInterval = null;

    let currentJobId = null;
    let pollInterval = null;
    const scanDataStore = {};

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

        const formData = new FormData();
        formData.append('file', file);
        
        uploadSection.classList.add('hidden');
        progressSection.classList.remove('hidden');
        scanActions.classList.remove('hidden');
        pauseBtn.classList.remove('hidden');
        resumeBtn.classList.add('hidden');
        
        fetch('/api/upload_ip', {
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
        }, 2000);
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
                window.location.href = `/api/download_ip/${currentJobId}`;
            };
            if(skipBtn) skipBtn.classList.add('hidden');
            if(troubleshootBtn) troubleshootBtn.classList.add('hidden');
            if(liveBtn) liveBtn.classList.add('hidden');
        } else if (status === 'paused') {
            scanStatusText.textContent = "Scan Paused";
            pauseBtn.classList.add('hidden');
            resumeBtn.classList.remove('hidden');
            if(skipBtn) skipBtn.classList.add('hidden');
            if(troubleshootBtn) troubleshootBtn.classList.add('hidden');
            if(liveBtn) liveBtn.classList.add('hidden');
        } else {
            scanStatusText.textContent = "Scanning...";
            pauseBtn.classList.remove('hidden');
            resumeBtn.classList.add('hidden');
            if(skipBtn) skipBtn.classList.remove('hidden');
            if(troubleshootBtn) troubleshootBtn.classList.remove('hidden');
            if(liveBtn) liveBtn.classList.remove('hidden');
        }
        
        const currentRowsCount = resultsBody.children.length;
        if (results.length > currentRowsCount) {
            for (let i = currentRowsCount; i < results.length; i++) {
                const res = results[i];
                const key = `${res.ip}`;
                scanDataStore[key] = res;
                
                const tr = document.createElement('tr');
                
                // IP
                const targetTd = document.createElement('td');
                targetTd.innerHTML = `<strong>${res.ip}</strong>`;
                
                // Accessibility Badge Mapping
                const accTd = document.createElement('td');
                if(res.accessibility.includes('Error') || res.accessibility.includes('aborted') || res.accessibility.includes('Blocked')) {
                    accTd.innerHTML = `<span class="badge badge-warning">${res.accessibility}</span>`;
                } else if(res.accessibility.includes('Not Accessible')) {
                    accTd.innerHTML = `<span class="badge badge-critical">${res.accessibility}</span>`;
                } else {
                    accTd.innerHTML = `<span class="badge badge-info" style="background: rgba(46,160,67,0.2); border-color: rgba(46,160,67,0.5);">${res.accessibility}</span>`;
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
                    window.location.href = `/api/download_target_raw/${currentJobId}/${res.ip}`;
                };
                
                actionTd.appendChild(viewBtn);
                actionTd.appendChild(dlBtn);
                
                tr.appendChild(targetTd);
                tr.appendChild(accTd);
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
        if (e.target === liveModal) {
            liveModal.classList.add('hidden');
            if (liveInterval) clearInterval(liveInterval);
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

    if (liveBtn) {
        liveBtn.onclick = () => {
            liveModal.classList.remove('hidden');
            pollLive();
            liveInterval = setInterval(pollLive, 1000);
        };
    }

    if (closeLiveModal) {
        closeLiveModal.onclick = () => {
            liveModal.classList.add('hidden');
            if (liveInterval) clearInterval(liveInterval);
        };
    }

    function pollLive() {
        if (!currentJobId) return;
        fetch(`/api/live/${currentJobId}`)
            .then(res => res.json())
            .then(data => {
                liveOutput.textContent = data.output;
                liveOutput.scrollTop = liveOutput.scrollHeight;
            })
            .catch(err => console.error(err));
    }

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
        if (confirm("Are you sure you want to abort the ping sweep?")) {
            sendAction('abort');
            scanActions.classList.add('hidden');
            scanStatusText.textContent = "Aborting...";
        }
    };
});

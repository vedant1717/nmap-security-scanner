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
    
    // Modal Elements
    const rawModal = document.getElementById('raw-modal');
    const closeModal = document.getElementById('close-modal');
    const modalCommand = document.getElementById('modal-command');
    const modalOutput = document.getElementById('modal-output');

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

        const formData = new FormData();
        formData.append('file', file);
        
        // Hide upload, show progress
        uploadSection.classList.add('hidden');
        progressSection.classList.remove('hidden');
        
        fetch('/api/upload', {
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
        
        if (status === 'completed') {
            clearInterval(pollInterval);
            scanStatusText.textContent = "Scan Completed!";
            downloadBtn.classList.remove('hidden');
            downloadBtn.onclick = () => {
                window.location.href = `/api/download/${currentJobId}`;
            };
        }
        
        // Render new results
        // Using a basic diff render: only append new rows
        const currentRowsCount = resultsBody.children.length;
        if (results.length > currentRowsCount) {
            for (let i = currentRowsCount; i < results.length; i++) {
                const res = results[i];
                const key = `${res.ip}:${res.port}`;
                scanDataStore[key] = res; // Save for modal
                
                const tr = document.createElement('tr');
                
                // IP & Port
                const targetTd = document.createElement('td');
                targetTd.innerHTML = `<div><strong>${res.ip}</strong></div><div class="text-sm">Port: ${res.port}</div>`;
                
                // Service & Version
                const serviceTd = document.createElement('td');
                serviceTd.textContent = `${res.service} ${res.version !== 'Unknown' && res.version !== 'N/A' && res.version ? 'v'+res.version : ''}`;
                
                // Findings
                const findingsTd = document.createElement('td');
                if (res.findings === 'No issues found') {
                    findingsTd.innerHTML = `<span class="badge badge-info">Clean</span>`;
                } else if (res.findings.includes('timed out') || res.findings.includes('closed') || res.findings.includes('error') || res.findings.includes('down')) {
                    findingsTd.innerHTML = `<span class="badge badge-warning">${res.findings}</span>`;
                } else {
                    const parsed = parseFindings(res.findings);
                    findingsTd.innerHTML = parsed;
                }
                
                // Action
                const actionTd = document.createElement('td');
                const viewBtn = document.createElement('button');
                viewBtn.className = 'btn-sm';
                viewBtn.textContent = 'View Output';
                viewBtn.onclick = () => openModal(key);
                actionTd.appendChild(viewBtn);
                
                tr.appendChild(targetTd);
                tr.appendChild(serviceTd);
                tr.appendChild(findingsTd);
                tr.appendChild(actionTd);
                
                resultsBody.appendChild(tr);
            }
        }
    }

    function parseFindings(findingsStr) {
        if (!findingsStr) return '';
        const items = findingsStr.split('; ');
        return items.map(item => {
            let className = 'badge-info';
            if (item.includes('CRITICAL') || item.includes('Expired')) className = 'badge-critical';
            else if (item.includes('WARNING') || item.includes('Weak') || item.includes('untrusted')) className = 'badge-warning';
            
            // Clean up the text by removing our own prepended tags
            let cleanItem = item.replace(/CRITICAL: |WARNING: |INFO: /, '');
            return `<span class="badge ${className}">${cleanItem}</span>`;
        }).join('');
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
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const scanBtn = document.getElementById('scan-btn');
    const filePreview = document.getElementById('file-preview');
    const fileNameEl = document.getElementById('file-name');
    const fileSizeEl = document.getElementById('file-size');
    const clearFileBtn = document.getElementById('clear-file');
    const scanSpinner = document.getElementById('scan-spinner');
    const scanBtnText = document.getElementById('scan-btn-text');
    const resultsPanel = document.getElementById('results-panel');
    const errorEl = document.getElementById('scan-error');

    let currentFile = null;

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-primary', 'bg-surface-container-high');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-primary', 'bg-surface-container-high');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-primary', 'bg-surface-container-high');
        if (e.dataTransfer.files.length) {
            handleFile(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length) {
            handleFile(e.target.files[0]);
        }
    });

    clearFileBtn.addEventListener('click', () => {
        currentFile = null;
        fileInput.value = '';
        dropZone.classList.remove('hidden');
        filePreview.classList.add('hidden');
        scanBtn.disabled = true;
        errorEl.classList.add('hidden');
        resultsPanel.style.display = 'none';
    });

    function handleFile(file) {
        if (!file.name.endsWith('.tf') && !file.name.endsWith('.json')) {
            showError('Invalid file type. Only .tf and .json allowed.');
            return;
        }
        if (file.size > 10 * 1024 * 1024) {
            showError('File exceeds 10MB limit.');
            return;
        }

        currentFile = file;
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = (file.size / 1024).toFixed(1) + ' KB';

        dropZone.classList.add('hidden');
        filePreview.classList.remove('hidden');
        scanBtn.disabled = false;
        errorEl.classList.add('hidden');
    }

    function showError(msg) {
        errorEl.textContent = msg;
        errorEl.classList.remove('hidden');
    }

    scanBtn.addEventListener('click', async () => {
        if (!currentFile) return;

        if (!App.state.apiKey) {
            showError('API Key is missing. Please configure it in Settings.');
            return;
        }

        scanBtn.disabled = true;
        scanSpinner.classList.remove('hidden');
        scanBtnText.textContent = 'SCANNING...';
        errorEl.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', currentFile);

        try {
            const res = await fetch(`${App.state.backendUrl}/scan`, {
                method: 'POST',
                headers: {
                    'X-API-Key': App.state.apiKey,
                    'Accept': 'application/json'
                },
                body: formData
            });

            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                throw new Error(data.detail || `Scan failed with status ${res.status}`);
            }

            const scanResult = await res.json();
            App.saveScan(scanResult);
            renderResults(scanResult);

        } catch (err) {
            showError(err.message);
        } finally {
            scanBtn.disabled = false;
            scanSpinner.classList.add('hidden');
            scanBtnText.textContent = 'RE-SCAN FILE';
        }
    });

    function escapeHtml(unsafe) {
        return (unsafe || "").toString()
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
    }

    function renderResults(data) {
        resultsPanel.style.display = 'block';

        // Update Gauge
        document.getElementById('scan-confidence').textContent = `CONFIDENCE: ${data.confidence || '--'}`;
        document.getElementById('risk-score').textContent = data.score;
        const deg = 180 + (data.score * 1.8); // 0 = 180deg, 100 = 360deg
        document.getElementById('risk-gauge').style.transform = `rotate(${deg}deg)`;

        // Update Breakdowns
        document.getElementById('rule-score-val').textContent = data.rule_based_score.toFixed(2);
        document.getElementById('rule-score-bar').style.width = `${data.rule_based_score}%`;

        document.getElementById('ml-score-val').textContent = data.ml_score.toFixed(2);
        document.getElementById('ml-score-bar').style.width = `${data.ml_score}%`;

        // Update Vulnerabilities Table
        const tbody = document.getElementById('vulns-table');
        tbody.innerHTML = '';

        if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center">No vulnerabilities found!</td></tr>';
            return;
        }

        data.vulnerabilities.forEach(v => {
            let colorCls = 'text-primary';
            let bgCls = 'bg-primary/10';
            let icon = 'info';

            if (v.severity === 'CRITICAL') { colorCls = 'text-error'; bgCls = 'bg-error/10'; icon = 'warning'; }
            else if (v.severity === 'HIGH') { colorCls = 'text-tertiary-container'; bgCls = 'bg-tertiary-container/10'; icon = 'report'; }
            else if (v.severity === 'MEDIUM') { colorCls = 'text-orange-400'; bgCls = 'bg-orange-400/10'; icon = 'warning'; }

            const safeMessage = escapeHtml(v.message);
            const safeResource = escapeHtml(v.resource);
            const safeRemediation = escapeHtml(v.remediation);
            const safePoints = escapeHtml(v.points || 0);

            const tr = document.createElement('tr');
            tr.className = 'hover:bg-surface-container-high transition-colors';
            tr.innerHTML = `
                <td class="px-6 py-4">
                    <span class="inline-flex items-center gap-1.5 ${bgCls} ${colorCls} px-2.5 py-1 rounded-full text-[10px] font-black">
                        <span class="material-symbols-outlined text-[14px]" data-icon="${icon}" style="font-variation-settings: 'FILL' 1;">${icon}</span>
                        ${v.severity}
                    </span>
                </td>
                <td class="px-6 py-4 font-medium">${safeMessage}</td>
                <td class="px-6 py-4 font-mono text-xs text-secondary">${safeResource}</td>
                <td class="px-6 py-4 text-xs text-on-surface-variant">${safeRemediation}</td>
                <td class="px-6 py-4 text-right font-mono font-bold ${colorCls}">${safePoints}</td>
            `;
            tbody.appendChild(tr);
        });
    }
});

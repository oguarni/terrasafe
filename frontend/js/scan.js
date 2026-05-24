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
    let pendingScan = false;

    // API key onboarding modal
    const apiKeyModal = document.getElementById('api-key-modal');
    const modalKeyInput = document.getElementById('modal-api-key-input');
    const modalSaveKey = document.getElementById('modal-save-key');
    const modalCloseKey = document.getElementById('modal-close-key');
    const modalKeyError = document.getElementById('modal-key-error');
    let lastFocusedBeforeModal = null;

    // Visible, tabbable controls inside the modal, in DOM order.
    function modalFocusable() {
        return Array.from(apiKeyModal.querySelectorAll(
            'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])'
        )).filter((el) => el.offsetParent !== null);
    }

    // While the modal is open: Escape closes it, and Tab is trapped so focus
    // cannot reach the page behind the overlay.
    function handleModalKeydown(e) {
        if (e.key === 'Escape') {
            e.preventDefault();
            closeKeyModal();
            return;
        }
        if (e.key !== 'Tab') return;
        const focusable = modalFocusable();
        if (focusable.length === 0) return;
        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
        }
    }

    function openKeyModal() {
        if (!apiKeyModal) return;
        lastFocusedBeforeModal = document.activeElement;
        modalKeyInput.value = App.state.apiKey || '';
        modalKeyError.classList.add('hidden');
        apiKeyModal.classList.remove('hidden');
        modalKeyInput.focus();
        document.addEventListener('keydown', handleModalKeydown);
    }

    function closeKeyModal() {
        if (!apiKeyModal) return;
        apiKeyModal.classList.add('hidden');
        document.removeEventListener('keydown', handleModalKeydown);
        if (lastFocusedBeforeModal && typeof lastFocusedBeforeModal.focus === 'function') {
            lastFocusedBeforeModal.focus();
        }
        lastFocusedBeforeModal = null;
    }

    function saveModalKey() {
        const val = modalKeyInput.value.trim();
        if (!val) {
            modalKeyError.textContent = 'Please enter an API key to continue.';
            modalKeyError.classList.remove('hidden');
            return;
        }
        App.state.apiKey = val;
        localStorage.setItem('apiKey', val);
        closeKeyModal();

        // Resume the scan the user attempted before being prompted for a key.
        if (pendingScan && currentFile) {
            pendingScan = false;
            scanBtn.click();
        }
    }

    if (modalSaveKey) modalSaveKey.addEventListener('click', saveModalKey);
    if (modalCloseKey) modalCloseKey.addEventListener('click', closeKeyModal);
    if (modalKeyInput) {
        modalKeyInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') saveModalKey();
        });
    }
    if (apiKeyModal) {
        apiKeyModal.addEventListener('click', (e) => {
            if (e.target === apiKeyModal) closeKeyModal();
        });
    }

    // Prompt immediately on load when no key is configured
    if (!App.state.apiKey) openKeyModal();

    // Load Demo Scan — render a pre-computed sample result, bypassing file
    // upload and API auth so visitors can explore the output instantly.
    function loadDemoAndRender() {
        const demo = App.loadDemo();
        errorEl.classList.add('hidden');
        renderResults(demo);
        resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    const demoBtn = document.getElementById('demo-btn');
    if (demoBtn) demoBtn.addEventListener('click', loadDemoAndRender);

    // Escape hatch from the API-key modal so first-time visitors are not
    // forced to enter a key before they can see what TerraVault produces.
    const modalDemoLink = document.getElementById('modal-demo-link');
    if (modalDemoLink) {
        modalDemoLink.addEventListener('click', (e) => {
            e.preventDefault();
            closeKeyModal();
            loadDemoAndRender();
        });
    }

    dropZone.addEventListener('click', () => fileInput.click());

    dropZone.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            fileInput.click();
        }
    });

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
            pendingScan = true;
            openKeyModal();
            return;
        }

        scanBtn.disabled = true;
        scanSpinner.classList.remove('hidden');
        scanBtnText.textContent = 'SCANNING...';
        errorEl.classList.add('hidden');

        const formData = new FormData();
        formData.append('file', currentFile);

        try {
            const res = await App.fetchWithTimeout(`${App.state.backendUrl}/scan`, {
                method: 'POST',
                headers: {
                    'X-API-Key': App.state.apiKey,
                    'Accept': 'application/json'
                },
                body: formData
            }, 30000);

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

    // Pure: maps a severity level to its distinct color, background, and icon.
    // Every level (CRITICAL/HIGH/MEDIUM/LOW/INFO) is visually distinguishable;
    // unknown levels fall back to the muted INFO style.
    function severityStyle(severity) {
        switch (severity) {
            case 'CRITICAL': return { color: 'text-error', bg: 'bg-error/10', icon: 'dangerous' };
            case 'HIGH': return { color: 'text-tertiary-container', bg: 'bg-tertiary-container/10', icon: 'report' };
            case 'MEDIUM': return { color: 'text-amber-400', bg: 'bg-amber-400/10', icon: 'warning' };
            case 'LOW': return { color: 'text-sky-400', bg: 'bg-sky-400/10', icon: 'arrow_downward' };
            default: return { color: 'text-on-surface-variant', bg: 'bg-on-surface-variant/10', icon: 'info' };
        }
    }

    // Pure: maps a 0-100 risk score to the gauge's rotation in degrees
    // (0 -> 180deg at the left, 100 -> 360deg at the right).
    function gaugeRotation(score) {
        return 180 + (Number(score) * 1.8);
    }

    function renderGauge(data) {
        document.getElementById('scan-confidence').textContent = `CONFIDENCE: ${data.confidence || '--'}`;
        document.getElementById('risk-score').textContent = data.score;
        document.getElementById('risk-gauge').style.transform = `rotate(${gaugeRotation(data.score)}deg)`;
    }

    function renderBreakdown(data) {
        document.getElementById('rule-score-val').textContent = data.rule_based_score.toFixed(2);
        document.getElementById('rule-score-bar').style.width = `${data.rule_based_score}%`;
        document.getElementById('ml-score-val').textContent = data.ml_score.toFixed(2);
        document.getElementById('ml-score-bar').style.width = `${data.ml_score}%`;
    }

    function buildVulnRow(v) {
        const style = severityStyle(v.severity);
        const safeSeverity = App.escapeHtml(v.severity);
        const safeMessage = App.escapeHtml(v.message);
        const safeResource = App.escapeHtml(v.resource);
        const safeRemediation = App.escapeHtml(v.remediation);
        const safePoints = App.escapeHtml(v.points || 0);

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-surface-container-high transition-colors';
        tr.innerHTML = `
            <td class="px-6 py-4">
                <span class="inline-flex items-center gap-1.5 ${style.bg} ${style.color} px-2.5 py-1 rounded-full text-[10px] font-black">
                    <span class="material-symbols-outlined text-[14px]" data-icon="${style.icon}" style="font-variation-settings: 'FILL' 1;">${style.icon}</span>
                    ${safeSeverity}
                </span>
            </td>
            <td class="px-6 py-4 font-medium">${safeMessage}</td>
            <td class="px-6 py-4 font-mono text-xs text-secondary">${safeResource}</td>
            <td class="px-6 py-4 text-xs text-on-surface-variant">${safeRemediation}</td>
            <td class="px-6 py-4 text-right font-mono font-bold ${style.color}">${safePoints}</td>
        `;
        return tr;
    }

    function renderVulnTable(vulnerabilities) {
        const tbody = document.getElementById('vulns-table');
        tbody.innerHTML = '';

        if (!vulnerabilities || vulnerabilities.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-4 text-center">No vulnerabilities found!</td></tr>';
            return;
        }

        vulnerabilities.forEach(v => tbody.appendChild(buildVulnRow(v)));
    }

    function renderResults(data) {
        resultsPanel.style.display = 'block';
        renderGauge(data);
        renderBreakdown(data);
        renderVulnTable(data.vulnerabilities);
    }
});

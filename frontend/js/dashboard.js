document.addEventListener('DOMContentLoaded', () => {
    const totalEl = document.getElementById('total-scans');
    const avgScoreEl = document.getElementById('avg-score');
    const totalVulnsEl = document.getElementById('total-vulns');
    const lastScanEl = document.getElementById('last-scan-time');
    const tableBody = document.getElementById('recent-scans-table');
    const sysStatus = document.getElementById('sys-status');
    const clearDemoBtn = document.getElementById('clear-demo-btn');

    // Pure: aggregate the scan list into the four headline metrics.
    function computeMetrics(scans) {
        const totalScore = scans.reduce((acc, s) => acc + s.score, 0);
        const totalVulns = scans.reduce((acc, s) => acc + (s.vulnerabilities ? s.vulnerabilities.length : 0), 0);
        return {
            count: scans.length,
            avg: Math.round(totalScore / scans.length),
            totalVulns,
            lastScan: new Date(scans[0].timestamp)
        };
    }

    // Pure: risk score -> progress-bar color token.
    function scoreBarColor(score) {
        if (score > 60) return 'bg-error';
        if (score > 30) return 'bg-tertiary-container';
        return 'bg-emerald-500';
    }

    // Pure: severity summary -> severity-pill markup (counts escaped).
    function severityPills(summary) {
        const fallback = '<span class="px-2 py-0.5 rounded-full bg-surface-container-highest text-on-surface-variant text-[10px] font-black">--</span>';
        if (!summary) return fallback;
        let html = '';
        if (summary.critical > 0) html += `<span class="px-2 py-0.5 rounded-full bg-error-container text-on-error-container text-[10px] font-black">${App.escapeHtml(summary.critical)}C</span> `;
        if (summary.high > 0) html += `<span class="px-2 py-0.5 rounded-full bg-tertiary-container text-on-tertiary-container text-[10px] font-black">${App.escapeHtml(summary.high)}H</span> `;
        if (summary.medium > 0) html += `<span class="px-2 py-0.5 rounded-full bg-secondary-container text-on-secondary-container text-[10px] font-black">${App.escapeHtml(summary.medium)}M</span> `;
        return html || fallback;
    }

    // Pure: timestamp -> compact "HH:MM / DD-MM" label.
    function formatRowTimestamp(date) {
        return `${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')} / ${date.getDate()}-${date.getMonth() + 1}`;
    }

    function wireDemoButton() {
        const btn = document.getElementById('demo-btn');
        if (btn) {
            btn.addEventListener('click', () => {
                App.loadDemo();
                updateDashboard();
            });
        }
    }

    function renderEmptyState() {
        totalEl.textContent = '0';
        avgScoreEl.textContent = '--';
        totalVulnsEl.textContent = '0';
        lastScanEl.textContent = '--';
        if (clearDemoBtn) clearDemoBtn.classList.add('hidden');
        tableBody.innerHTML = `
            <tr><td colspan="5" class="px-6 py-10 text-center">
                <p class="text-on-surface-variant text-sm mb-5">No scans yet &mdash; your scan history is kept locally in this browser.</p>
                <button id="demo-btn" class="inline-flex items-center gap-2 bg-primary/10 text-primary font-semibold px-5 py-2.5 rounded-full hover:bg-primary/20 transition-all active:scale-[0.98]">
                    <span class="material-symbols-outlined text-lg" data-icon="auto_awesome">auto_awesome</span>
                    Load Demo Scan
                </button>
                <p class="text-xs text-on-surface-variant/50 mt-3">Loads a sample vulnerable.tf result so you can explore the dashboard.</p>
            </td></tr>`;
        wireDemoButton();
    }

    function renderMetrics(metrics) {
        totalEl.textContent = metrics.count.toString().padStart(2, '0');
        avgScoreEl.textContent = metrics.avg.toString();
        totalVulnsEl.textContent = metrics.totalVulns.toString();
        lastScanEl.textContent = metrics.lastScan.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        sysStatus.textContent = `SYSTEM_STATUS: OPERATIONAL // LAST_SYNC: ${metrics.lastScan.toLocaleTimeString()}`;
    }

    function buildScanRow(scan) {
        const barColor = scoreBarColor(scan.score);
        const safeFile = App.escapeHtml(scan.file || 'unknown.tf');
        const safeScore = App.escapeHtml(scan.score);
        const safeConfidence = App.escapeHtml(scan.confidence || 'N/A');

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-surface-container-high transition-colors group';
        tr.innerHTML = `
            <td class="px-6 py-5">
                <div class="flex items-center gap-3">
                    <span class="material-symbols-outlined text-primary text-lg shrink-0" data-icon="description">description</span>
                    <span class="font-mono text-sm truncate max-w-[220px]" title="${safeFile}">${safeFile}</span>
                    ${scan.demo ? '<span class="px-1.5 py-0.5 rounded bg-primary/15 text-primary text-[9px] font-black tracking-wider shrink-0">DEMO</span>' : ''}
                </div>
            </td>
            <td class="px-6 py-5">
                <div class="flex items-center gap-2">
                    <div class="w-12 h-1.5 bg-surface-container-highest rounded-full overflow-hidden">
                        <div class="h-full ${barColor}" style="width: ${safeScore}%"></div>
                    </div>
                    <span class="font-bold ${barColor.replace('bg-', 'text-')}">${safeScore}</span>
                </div>
            </td>
            <td class="px-6 py-5">
                <div class="flex gap-1.5">${severityPills(scan.summary)}</div>
            </td>
            <td class="px-6 py-5 text-on-surface-variant font-mono text-xs">${safeConfidence}</td>
            <td class="px-6 py-5 text-right font-mono text-xs text-on-surface-variant">${formatRowTimestamp(new Date(scan.timestamp))}</td>
        `;
        return tr;
    }

    function renderRecentTable(scans) {
        tableBody.innerHTML = '';
        scans.slice(0, 5).forEach(scan => tableBody.appendChild(buildScanRow(scan)));
    }

    function updateDashboard() {
        const scans = App.state.scans;
        if (!scans || scans.length === 0) {
            renderEmptyState();
            return;
        }
        renderMetrics(computeMetrics(scans));
        renderRecentTable(scans);
        if (clearDemoBtn) clearDemoBtn.classList.toggle('hidden', !App.hasDemo());
    }

    // Initial render
    updateDashboard();

    if (clearDemoBtn) {
        clearDemoBtn.addEventListener('click', () => {
            App.clearDemo();
            updateDashboard();
        });
    }

    // Re-render periodically to catch cross-tab saves
    window.addEventListener('storage', (e) => {
        if (e.key === 'scans') {
            try {
                App.state.scans = JSON.parse(e.newValue || '[]');
            } catch (err) {
                // Another tab wrote malformed JSON; keep the dashboard alive.
                console.warn('Corrupt scan data received from another tab. Ignoring update.');
                App.state.scans = [];
            }
            updateDashboard();
        }
    });
});

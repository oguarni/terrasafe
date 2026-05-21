document.addEventListener('DOMContentLoaded', () => {
    const totalEl = document.getElementById('total-scans');
    const avgScoreEl = document.getElementById('avg-score');
    const totalVulnsEl = document.getElementById('total-vulns');
    const lastScanEl = document.getElementById('last-scan-time');
    const tableBody = document.getElementById('recent-scans-table');
    const sysStatus = document.getElementById('sys-status');
    const clearDemoBtn = document.getElementById('clear-demo-btn');

    function escapeHtml(unsafe) {
        return (unsafe || "").toString()
             .replace(/&/g, "&amp;")
             .replace(/</g, "&lt;")
             .replace(/>/g, "&gt;")
             .replace(/"/g, "&quot;")
             .replace(/'/g, "&#039;");
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

    function updateDashboard() {
        const scans = App.state.scans;
        if (!scans || scans.length === 0) {
            renderEmptyState();
            return;
        }

        totalEl.textContent = scans.length.toString().padStart(2, '0');

        const totalScore = scans.reduce((acc, s) => acc + s.score, 0);
        const avg = Math.round(totalScore / scans.length);
        avgScoreEl.textContent = avg.toString();

        const totalVulns = scans.reduce((acc, s) => {
            return acc + (s.vulnerabilities ? s.vulnerabilities.length : 0);
        }, 0);
        totalVulnsEl.textContent = totalVulns.toString();

        const last = new Date(scans[0].timestamp);
        lastScanEl.textContent = last.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});

        sysStatus.textContent = `SYSTEM_STATUS: OPERATIONAL // LAST_SYNC: ${last.toLocaleTimeString()}`;

        // Populate table (up to 5)
        tableBody.innerHTML = '';
        scans.slice(0, 5).forEach(scan => {
            const date = new Date(scan.timestamp);
            const formattedDate = `${date.getHours()}:${date.getMinutes().toString().padStart(2,'0')} / ${date.getDate()}-${date.getMonth()+1}`;

            let barColor = 'bg-emerald-500';
            if(scan.score > 60) barColor = 'bg-error';
            else if(scan.score > 30) barColor = 'bg-tertiary-container';

            let pillHtml = '';
            if (scan.summary) {
                if (scan.summary.critical > 0) pillHtml += `<span class="px-2 py-0.5 rounded-full bg-error-container text-on-error-container text-[10px] font-black">${scan.summary.critical}C</span> `;
                if (scan.summary.high > 0) pillHtml += `<span class="px-2 py-0.5 rounded-full bg-tertiary-container text-on-tertiary-container text-[10px] font-black">${scan.summary.high}H</span> `;
                if (scan.summary.medium > 0) pillHtml += `<span class="px-2 py-0.5 rounded-full bg-secondary-container text-on-secondary-container text-[10px] font-black">${scan.summary.medium}M</span> `;
            }
            if(!pillHtml) pillHtml = `<span class="px-2 py-0.5 rounded-full bg-surface-container-highest text-on-surface-variant text-[10px] font-black">--</span>`;

            const safeFile = escapeHtml(scan.file || 'unknown.tf');
            const safeScore = escapeHtml(scan.score);
            const safeConfidence = escapeHtml(scan.confidence || 'N/A');

            const tr = document.createElement('tr');
            tr.className = 'hover:bg-surface-container-high transition-colors group';
            tr.innerHTML = `
                <td class="px-6 py-5">
                    <div class="flex items-center gap-3">
                        <span class="material-symbols-outlined text-primary text-lg" data-icon="description">description</span>
                        <span class="font-mono text-sm">${safeFile}</span>
                        ${scan.demo ? '<span class="px-1.5 py-0.5 rounded bg-primary/15 text-primary text-[9px] font-black tracking-wider">DEMO</span>' : ''}
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
                    <div class="flex gap-1.5">${pillHtml}</div>
                </td>
                <td class="px-6 py-5 text-on-surface-variant font-mono text-xs">${safeConfidence}</td>
                <td class="px-6 py-5 text-right font-mono text-xs text-on-surface-variant">${formattedDate}</td>
            `;
            tableBody.appendChild(tr);
        });

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
            App.state.scans = JSON.parse(e.newValue || '[]');
            updateDashboard();
        }
    });
});

const App = {
    state: {
        backendUrl: localStorage.getItem('backendUrl') || '',
        apiKey: localStorage.getItem('apiKey') || '',
        theme: localStorage.getItem('theme') || 'dark',
        scans: JSON.parse(localStorage.getItem('scans') || '[]'),
        sysOk: false
    },

    init() {
        this.applyTheme(this.state.theme);
        this.bindEvents();
        this.checkHealth();
        // check health periodically
        setInterval(() => this.checkHealth(), 30000);
    },

    bindEvents() {
        const toggle = document.getElementById('theme-toggle');
        if (toggle) {
            toggle.addEventListener('click', () => {
                const newTheme = this.state.theme === 'dark' ? 'light' : 'dark';
                this.applyTheme(newTheme);
            });
        }
    },

    applyTheme(theme) {
        this.state.theme = theme;
        localStorage.setItem('theme', theme);
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
        }
    },

    async checkHealth() {
        const indicatorDot = document.querySelector('.indicator-dot');
        const indicatorText = document.querySelector('.indicator-text');

        try {
            const res = await fetch(`${this.state.backendUrl}/health`, {
                headers: { 'Accept': 'application/json' }
            });
            if (res.ok) {
                this.state.sysOk = true;
                if(indicatorDot) {
                    indicatorDot.className = 'w-2 h-2 rounded-full bg-green-500 indicator-dot animate-pulse';
                    indicatorText.className = 'text-[10px] font-mono uppercase tracking-widest text-green-500 indicator-text';
                    indicatorText.textContent = 'SYS_OK';
                }
            } else {
                throw new Error('Not OK');
            }
        } catch (e) {
            this.state.sysOk = false;
            if(indicatorDot) {
                indicatorDot.className = 'w-2 h-2 rounded-full bg-red-500 indicator-dot';
                indicatorText.className = 'text-[10px] font-mono uppercase tracking-widest text-red-500 indicator-text';
                indicatorText.textContent = 'OFFLINE';
            }
        }
    },

    saveScan(scanData) {
        // scanData structure expected to match backend JSON response
        const newScan = {
            id: Date.now(),
            timestamp: new Date().toISOString(),
            ...scanData
        };
        this.state.scans.unshift(newScan);
        // keep only latest 50
        if (this.state.scans.length > 50) this.state.scans.pop();
        localStorage.setItem('scans', JSON.stringify(this.state.scans));
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());
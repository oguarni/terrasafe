const App = {
    state: {
        backendUrl: localStorage.getItem('backendUrl') || window.location.origin,
        apiKey: localStorage.getItem('apiKey') || '',
        theme: localStorage.getItem('theme') || 'dark',
        scans: (() => {
            try { return JSON.parse(localStorage.getItem('scans') || '[]'); }
            catch (e) {
                console.warn('Corrupt scan data detected. Resetting history.');
                localStorage.removeItem('scans');
                return [];
            }
        })(),
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

        const mobileToggle = document.getElementById('mobile-nav-toggle');
        const mobileNav = document.getElementById('mobile-nav');
        if (mobileToggle && mobileNav) {
            mobileToggle.addEventListener('click', () => {
                const isOpen = !mobileNav.classList.toggle('hidden');
                mobileToggle.setAttribute('aria-expanded', String(isOpen));
                const icon = mobileToggle.querySelector('.material-symbols-outlined');
                if (icon) icon.textContent = isOpen ? 'close' : 'menu';
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

    // Single source of truth for HTML escaping, shared across pages. Returns
    // '' only for null/undefined so falsy-but-valid values like 0 survive.
    escapeHtml(unsafe) {
        if (unsafe === null || unsafe === undefined) return '';
        return unsafe.toString()
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    },

    // fetch() with an abort-based timeout. Translates the two failure modes the
    // user cannot otherwise diagnose — unreachable backend and hung backend —
    // into friendly, actionable messages. Non-OK HTTP responses are returned
    // as-is so callers can read status-specific error detail.
    async fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        try {
            return await fetch(url, { ...options, signal: controller.signal });
        } catch (err) {
            if (err.name === 'AbortError') {
                throw new Error('The request timed out. Please verify the backend service is running.');
            }
            throw new Error('Unable to reach the backend service. Please verify it is running and the endpoint is correct in Settings.');
        } finally {
            clearTimeout(timer);
        }
    },

    async checkHealth() {
        const indicatorDot = document.querySelector('.indicator-dot');
        const indicatorText = document.querySelector('.indicator-text');

        try {
            const res = await this.fetchWithTimeout(`${this.state.backendUrl}/health`, {
                headers: { 'Accept': 'application/json' }
            }, 8000);
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
    },

    // Pre-computed scan of test_files/vulnerable.tf, matching the backend
    // /scan JSON contract, so visitors can see a populated dashboard, risk
    // gauge, intelligence breakdown, and vulnerability table in one click —
    // no file upload or API key required.
    demoScan: {
        file: 'vulnerable.tf',
        score: 81,
        rule_based_score: 100,
        ml_score: 53.3,
        confidence: 'LOW',
        summary: { critical: 2, high: 4, medium: 2, low: 0, info: 0 },
        vulnerabilities: [
            { severity: 'CRITICAL', points: 30, message: 'Open security group - SSH port 22 exposed to internet', resource: 'web_sg', remediation: 'Restrict SSH access to specific IP ranges' },
            { severity: 'CRITICAL', points: 30, message: 'Hardcoded password detected', resource: 'Database/Instance', remediation: 'Use variables or secrets manager for sensitive data' },
            { severity: 'HIGH', points: 20, message: 'Unencrypted RDS instance', resource: 'main_db', remediation: 'Enable storage_encrypted = true' },
            { severity: 'HIGH', points: 20, message: 'Unencrypted EBS volume', resource: 'data_volume', remediation: 'Enable encrypted = true' },
            { severity: 'HIGH', points: 20, message: 'S3 bucket with public access enabled', resource: 'public_bucket', remediation: 'Enable all public access blocks' },
            { severity: 'HIGH', points: 20, message: 'Missing logging - no CloudTrail or CloudWatch log group detected', resource: 'Logging', remediation: 'Add aws_cloudtrail or aws_cloudwatch_log_group to enable audit logging' },
            { severity: 'MEDIUM', points: 10, message: 'HTTP/HTTPS port 80 open to internet', resource: 'web_sg', remediation: 'Consider using a CDN or WAF for public web services' },
            { severity: 'MEDIUM', points: 10, message: 'Missing VPC flow logs - aws_vpc present but no aws_flow_log detected', resource: 'VPC', remediation: 'Add an aws_flow_log resource to enable VPC traffic logging' }
        ]
    },

    hasDemo() {
        return this.state.scans.some(s => s.demo);
    },

    loadDemo() {
        let demo = this.state.scans.find(s => s.demo);
        if (!demo) {
            demo = { id: 'demo', timestamp: new Date().toISOString(), demo: true, ...this.demoScan };
            this.state.scans.unshift(demo);
            if (this.state.scans.length > 50) this.state.scans.pop();
            localStorage.setItem('scans', JSON.stringify(this.state.scans));
        }
        return demo;
    },

    clearDemo() {
        const before = this.state.scans.length;
        this.state.scans = this.state.scans.filter(s => !s.demo);
        if (this.state.scans.length !== before) {
            localStorage.setItem('scans', JSON.stringify(this.state.scans));
        }
    }
};

document.addEventListener('DOMContentLoaded', () => App.init());
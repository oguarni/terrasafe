document.addEventListener('DOMContentLoaded', () => {
    const apiKeyInput = document.getElementById('api-key-input');
    const backendUrlInput = document.getElementById('backend-url-input');
    const toggleKeyVisibility = document.getElementById('toggle-key-visibility');

    function showSaved(inputEl, isKey) {
        let badge = inputEl.parentElement.querySelector('.save-badge');
        if (!badge) {
            badge = document.createElement('span');
            badge.className = `save-badge absolute ${isKey ? 'right-12' : 'right-3'} top-3 text-[10px] font-bold text-green-500 uppercase tracking-widest opacity-0 transition-opacity duration-300 pointer-events-none`;
            badge.textContent = 'SAVED';
            inputEl.parentElement.classList.add('relative');
            inputEl.parentElement.appendChild(badge);
        }
        badge.classList.remove('opacity-0');
        clearTimeout(inputEl.saveTimeout);
        inputEl.saveTimeout = setTimeout(() => badge.classList.add('opacity-0'), 2000);
    }

    if (apiKeyInput) {
        apiKeyInput.value = App.state.apiKey;
        apiKeyInput.addEventListener('input', (e) => {
            const val = e.target.value;
            App.state.apiKey = val;
            localStorage.setItem('apiKey', val);
            showSaved(apiKeyInput, true);
        });
    }

    if (backendUrlInput) {
        backendUrlInput.value = App.state.backendUrl;
        backendUrlInput.addEventListener('input', (e) => {
            const val = e.target.value;
            App.state.backendUrl = val;
            localStorage.setItem('backendUrl', val);
            showSaved(backendUrlInput, false);
        });
    }

    if (toggleKeyVisibility) {
        toggleKeyVisibility.addEventListener('click', () => {
            if (apiKeyInput.type === 'password') {
                apiKeyInput.type = 'text';
                toggleKeyVisibility.querySelector('span').textContent = 'visibility_off';
            } else {
                apiKeyInput.type = 'password';
                toggleKeyVisibility.querySelector('span').textContent = 'visibility';
            }
        });
    }

    const revokeDataBtn = document.getElementById('revoke-data-btn');
    if (revokeDataBtn) {
        revokeDataBtn.addEventListener('click', () => {
            const confirmed = window.confirm(
                'Permanently delete all local data (API key, backend URL, and scan history) from this browser? This cannot be undone.'
            );
            if (confirmed) {
                localStorage.clear();
                window.location.reload();
            }
        });
    }

    // Keep the sidebar highlight on the section matching the current hash
    // (falling back to the first link). Toggles color only — the constant
    // border-l-4 avoids any layout shift between states.
    const sidebarLinks = document.querySelectorAll('#settings-sidebar a[href^="#"]');
    if (sidebarLinks.length) {
        const ACTIVE = ['bg-surface-container-high', 'text-primary', 'border-primary'];
        const INACTIVE = ['text-on-surface-variant', 'hover:bg-surface-container', 'border-transparent'];
        const syncSidebar = () => {
            const current = Array.from(sidebarLinks).find(
                (link) => link.getAttribute('href') === window.location.hash
            ) || sidebarLinks[0];
            sidebarLinks.forEach((link) => {
                const isActive = link === current;
                ACTIVE.forEach((cls) => link.classList.toggle(cls, isActive));
                INACTIVE.forEach((cls) => link.classList.toggle(cls, !isActive));
            });
        };
        window.addEventListener('hashchange', syncSidebar);
        syncSidebar();
    }
});
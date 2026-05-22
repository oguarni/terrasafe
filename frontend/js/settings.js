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
});
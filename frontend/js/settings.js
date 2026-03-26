document.addEventListener('DOMContentLoaded', () => {
    const apiKeyInput = document.getElementById('api-key-input');
    const backendUrlInput = document.getElementById('backend-url-input');
    const toggleKeyVisibility = document.getElementById('toggle-key-visibility');

    if (apiKeyInput) {
        apiKeyInput.value = App.state.apiKey;
        apiKeyInput.addEventListener('input', (e) => {
            const val = e.target.value;
            App.state.apiKey = val;
            localStorage.setItem('apiKey', val);
        });
    }

    if (backendUrlInput) {
        backendUrlInput.value = App.state.backendUrl;
        backendUrlInput.addEventListener('input', (e) => {
            const val = e.target.value;
            App.state.backendUrl = val;
            localStorage.setItem('backendUrl', val);
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
document.addEventListener('DOMContentLoaded', function() {
    const API_BASE = 'http://127.0.0.1:8787';
    
    // Get current tab domain
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const url = new URL(tabs[0].url);
        const domain = url.hostname;
        document.getElementById('current-domain').innerHTML = `<strong>Domain:</strong> ${domain}`;
        
        // Load saved settings
        chrome.storage.sync.get(['device', 'token'], function(result) {
            if (result.device) document.getElementById('device').value = result.device;
            if (result.token) document.getElementById('token').value = result.token;
        });
    });
    
    // Allow domain
    document.getElementById('allow-btn').addEventListener('click', function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const url = new URL(tabs[0].url);
            const domain = url.hostname;
            const device = document.getElementById('device').value;
            const token = document.getElementById('token').value;
            const ttl_hours = parseInt(document.getElementById('ttl').value);
            
            if (!device || !token) {
                showStatus('Please enter device ID and token', 'error');
                return;
            }
            
            // Save settings
            chrome.storage.sync.set({device: device, token: token});
            
            // Send request
            fetch(`${API_BASE}/approve`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain: domain,
                    device: device,
                    token: token,
                    ttl_hours: ttl_hours
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.ok) {
                    showStatus(`Domain allowed for ${data.ttl_hours} hours`, 'success');
                } else {
                    showStatus(`Failed: ${data.reason}`, 'error');
                }
            })
            .catch(error => {
                showStatus(`Error: ${error.message}`, 'error');
            });
        });
    });
    
    // Revoke domain
    document.getElementById('revoke-btn').addEventListener('click', function() {
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            const url = new URL(tabs[0].url);
            const domain = url.hostname;
            const device = document.getElementById('device').value;
            const token = document.getElementById('token').value;
            
            if (!device || !token) {
                showStatus('Please enter device ID and token', 'error');
                return;
            }
            
            fetch(`${API_BASE}/revoke`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    domain: domain,
                    device: device,
                    token: token
                })
            })
            .then(response => response.json())
            .then(data => {
                if (data.ok) {
                    showStatus('Domain revoked', 'success');
                } else {
                    showStatus(`Failed: ${data.reason}`, 'error');
                }
            })
            .catch(error => {
                showStatus(`Error: ${error.message}`, 'error');
            });
        });
    });
    
    function showStatus(message, type) {
        const statusDiv = document.getElementById('status');
        statusDiv.innerHTML = `<div class="status ${type}">${message}</div>`;
        setTimeout(() => {
            statusDiv.innerHTML = '';
        }, 5000);
    }
});
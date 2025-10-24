// VPN TOTP Helper - Chrome Extension Script

// No default secrets - users must provide their own for security

// Base32 decode function
function base32Decode(encoded) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = '';
    
    // Remove padding and convert to uppercase
    encoded = encoded.replace(/=+$/, '').toUpperCase();
    
    // Convert each character to 5-bit binary
    for (let i = 0; i < encoded.length; i++) {
        const val = alphabet.indexOf(encoded.charAt(i));
        if (val === -1) throw new Error('Invalid base32 character');
        bits += val.toString(2).padStart(5, '0');
    }
    
    // Convert bits to bytes
    const bytes = new Uint8Array(Math.floor(bits.length / 8));
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(bits.substr(i * 8, 8), 2);
    }
    
    return bytes;
}

// HMAC-SHA1 implementation
async function hmacSha1(key, message) {
    const cryptoKey = await crypto.subtle.importKey(
        'raw',
        key,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );
    
    const signature = await crypto.subtle.sign('HMAC', cryptoKey, message);
    return new Uint8Array(signature);
}

// Generate TOTP with optional time offset
async function generateTOTP(secret, timeOffset = 0, timeStep = 30) {
    try {
        // Decode the secret
        const key = base32Decode(secret);
        
        // Get current time counter with optional offset
        const currentTime = Math.floor(Date.now() / 1000) + timeOffset;
        const timeCounter = Math.floor(currentTime / timeStep);
        
        // Convert time to 8-byte array (big-endian)
        const timeBytes = new ArrayBuffer(8);
        const timeView = new DataView(timeBytes);
        timeView.setUint32(4, timeCounter, false); // big-endian
        
        // Generate HMAC-SHA1
        const hmacResult = await hmacSha1(key, new Uint8Array(timeBytes));
        
        // Dynamic truncation
        const offset = hmacResult[hmacResult.length - 1] & 0x0f;
        const code = ((hmacResult[offset] & 0x7f) << 24) |
                    ((hmacResult[offset + 1] & 0xff) << 16) |
                    ((hmacResult[offset + 2] & 0xff) << 8) |
                    (hmacResult[offset + 3] & 0xff);
        
        // Generate 6-digit code
        const totp = (code % 1000000).toString().padStart(6, '0');
        return totp;
    } catch (error) {
        console.error('TOTP generation failed:', error);
        return 'ERROR';
    }
}

// Calculate time remaining until next TOTP
function getTimeRemaining() {
    const currentTime = Math.floor(Date.now() / 1000);
    return 30 - (currentTime % 30);
}

// Copy text to clipboard
async function copyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch (err) {
        console.error('Failed to copy:', err);
        return false;
    }
}

// Save settings to browser storage
function saveSettings() {
    const totpSecret = document.getElementById('totp-secret').value.trim();
    const timeOffset = parseInt(document.getElementById('time-offset').value) || 0;
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const copyFormat = document.querySelector('.format-btn.active').dataset.format;
    
    if (!totpSecret || !username || !password) {
        alert('Please enter TOTP secret, username, and password');
        return;
    }
    
    // Validate TOTP secret (should be Base32)
    const base32Regex = /^[A-Z2-7]+=*$/;
    if (!base32Regex.test(totpSecret.toUpperCase())) {
        alert('Invalid TOTP secret. Please enter a valid Base32 encoded secret.');
        return;
    }
    
    // Save to localStorage
    localStorage.setItem('vpn_totp_secret', totpSecret.toUpperCase());
    localStorage.setItem('vpn_time_offset', timeOffset.toString());
    localStorage.setItem('vpn_username', username);
    localStorage.setItem('vpn_password', password);
    localStorage.setItem('vpn_copy_format', copyFormat);
    
    // Update display
    updateCredentialsDisplay();
    
    // Hide settings automatically after save
    const settingsSection = document.getElementById('settings-section');
    const toggleBtn = document.getElementById('toggle-settings');
    settingsSection.classList.add('hidden');
    toggleBtn.textContent = 'Show Settings';
    
    // Show feedback
    const saveBtn = document.getElementById('save-settings');
    const originalText = saveBtn.textContent;
    const originalBackground = saveBtn.style.background;
    saveBtn.textContent = 'Saved';
    saveBtn.style.background = '#198754';
    
    setTimeout(() => {
        saveBtn.textContent = originalText;
        saveBtn.style.background = originalBackground || '#198754';
    }, 1500);
}

// Load settings from browser storage
function loadSettings() {
    const totpSecret = localStorage.getItem('vpn_totp_secret') || '';
    const timeOffset = parseInt(localStorage.getItem('vpn_time_offset')) || 0;
    const username = localStorage.getItem('vpn_username') || '';
    const password = localStorage.getItem('vpn_password') || '';
    const copyFormat = localStorage.getItem('vpn_copy_format') || 'totp-first';
    
    // Only populate fields if they exist in the DOM
    const totpField = document.getElementById('totp-secret');
    const timeOffsetField = document.getElementById('time-offset');
    const usernameField = document.getElementById('username');
    const passwordField = document.getElementById('password');
    
    if (totpField) totpField.value = totpSecret;
    if (timeOffsetField) timeOffsetField.value = timeOffset;
    if (usernameField) usernameField.value = username;
    if (passwordField) passwordField.value = password;
    
    // Set format buttons
    document.querySelectorAll('.format-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.dataset.format === copyFormat) {
            btn.classList.add('active');
        }
    });
    
    return { totpSecret, timeOffset, username, password, copyFormat };
}

// Update credentials display
async function updateCredentialsDisplay() {
    const settings = loadSettings();
    
    // Check if all required settings are present
    if (!settings.totpSecret || !settings.username || !settings.password) {
        document.getElementById('current-totp').textContent = 'Setup Required';
        document.getElementById('copy-auth').disabled = true;
        document.getElementById('countdown').textContent = '--';
        return;
    }
    
    const totp = await generateTOTP(settings.totpSecret, settings.timeOffset);
    
    // Update display elements
    document.getElementById('current-totp').textContent = totp;
    
    if (settings.password && totp !== 'ERROR') {
        document.getElementById('copy-auth').disabled = false;
        // Update button text based on format
        const copyBtn = document.getElementById('copy-auth');
        if (settings.copyFormat === 'password-first') {
            copyBtn.textContent = 'Copy Password+TOTP';
        } else {
            copyBtn.textContent = 'Copy TOTP+Password';
        }
    } else {
        document.getElementById('copy-auth').disabled = true;
    }
    
    // Update countdown
    const timeRemaining = getTimeRemaining();
    document.getElementById('countdown').textContent = timeRemaining;
}

// Show button feedback
function showButtonFeedback(button, success = true) {
    const originalText = button.textContent;
    button.textContent = success ? 'Copied' : 'Failed';
    button.classList.add('copied');
    
    setTimeout(() => {
        button.textContent = originalText;
        button.classList.remove('copied');
    }, 1500);
}

// Initialize the extension
document.addEventListener('DOMContentLoaded', async () => {
    // Load saved settings
    loadSettings();
    
    // Initial credentials display
    await updateCredentialsDisplay();
    
    // Set up toggle settings button
    document.getElementById('toggle-settings').addEventListener('click', () => {
        const settingsSection = document.getElementById('settings-section');
        const toggleBtn = document.getElementById('toggle-settings');
        
        if (settingsSection.classList.contains('hidden')) {
            settingsSection.classList.remove('hidden');
            toggleBtn.textContent = 'Hide Settings';
        } else {
            settingsSection.classList.add('hidden');
            toggleBtn.textContent = 'Show Settings';
        }
    });
    
    // Set up save settings button
    document.getElementById('save-settings').addEventListener('click', saveSettings);
    
    // Set up format toggle buttons
    document.querySelectorAll('.format-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            // Remove active class from all buttons
            document.querySelectorAll('.format-btn').forEach(b => b.classList.remove('active'));
            // Add active class to clicked button
            btn.classList.add('active');
            // Auto-save the format preference
            const copyFormat = btn.dataset.format;
            localStorage.setItem('vpn_copy_format', copyFormat);
            // Update display to reflect new button text
            updateCredentialsDisplay();
        });
    });
    
    // Set up copy button
    document.getElementById('copy-auth').addEventListener('click', async () => {
        const button = document.getElementById('copy-auth');
        const settings = loadSettings();
        
        if (!settings.totpSecret || !settings.username || !settings.password) {
            alert('Please configure all settings first:\n1. Enter your TOTP secret key\n2. Enter your username\n3. Enter your password');
            // Show settings if they're hidden
            const settingsSection = document.getElementById('settings-section');
            const toggleBtn = document.getElementById('toggle-settings');
            if (settingsSection.classList.contains('hidden')) {
                settingsSection.classList.remove('hidden');
                toggleBtn.textContent = 'Hide Settings';
            }
            return;
        }
        
        const totp = await generateTOTP(settings.totpSecret, settings.timeOffset);
        
        if (totp === 'ERROR') {
            alert('Error generating TOTP. Please check your secret key.');
            return;
        }
        
        // Create the authentication string based on format preference
        let fullAuth;
        if (settings.copyFormat === 'password-first') {
            fullAuth = settings.password + totp;
        } else {
            fullAuth = totp + settings.password;
        }
        
        const success = await copyToClipboard(fullAuth);
        showButtonFeedback(button, success);
    });
    
    // Auto-save when Enter is pressed in input fields
    document.getElementById('totp-secret').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') saveSettings();
    });
    
    document.getElementById('time-offset').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') saveSettings();
    });
    
    document.getElementById('username').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') saveSettings();
    });
    
    document.getElementById('password').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') saveSettings();
    });
    
    // Update display every second for countdown
    setInterval(async () => {
        const timeRemaining = getTimeRemaining();
        document.getElementById('countdown').textContent = timeRemaining;
        
        // Regenerate TOTP when it expires
        if (timeRemaining === 30 || timeRemaining === 29) {
            await updateCredentialsDisplay();
        }
    }, 1000);
});

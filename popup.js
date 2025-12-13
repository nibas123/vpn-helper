

// QR Code scanning variables
let cameraStream = null;
let scanningInterval = null;

// Parse TOTP URI from QR code
function parseTOTPUri(uri) {
    try {
        // Log the scanned data for debugging
        console.log('Scanned QR data:', uri);
        console.log('QR data type:', typeof uri, 'Length:', uri?.length);
        
        // Check if it's already just a secret (raw base32 string)
        if (uri && !uri.includes(':') && /^[A-Z2-7]+=*$/i.test(uri)) {
            console.log('Detected as plain Base32 secret');
            return {
                secret: uri.toUpperCase(),
                issuer: '',
                label: ''
            };
        }
        
        // Handle Google Authenticator migration format
        if (uri.startsWith('otpauth-migration://')) {
            console.log('Detected Google Authenticator migration format');
            return parseGoogleAuthMigration(uri);
        }
        
        // TOTP URI format: otpauth://totp/Label?secret=SECRET&issuer=Issuer
        const url = new URL(uri);
        console.log('URL protocol:', url.protocol);
        
        if (url.protocol !== 'otpauth:') {
            throw new Error('Not a valid OTP auth URI. Expected otpauth:// or otpauth-migration:// format');
        }
        
        const secret = url.searchParams.get('secret');
        if (!secret) {
            throw new Error('No secret found in QR code');
        }
        
        return {
            secret: secret.toUpperCase(),
            issuer: url.searchParams.get('issuer') || '',
            label: decodeURIComponent(url.pathname.replace(/^\/totp\/|^\/hotp\//i, ''))
        };
    } catch (error) {
        console.error('Parse error:', error);
        // If it looks like it might be a plain secret, try to use it
        if (uri && typeof uri === 'string' && /^[A-Z2-7]+=*$/i.test(uri.trim())) {
            return {
                secret: uri.trim().toUpperCase(),
                issuer: '',
                label: ''
            };
        }
        throw new Error('Invalid TOTP QR code format. Expected otpauth:// URI or base32 secret');
    }
}

// Parse Google Authenticator migration QR code
function parseGoogleAuthMigration(uri) {
    try {
        console.log('Parsing Google Auth migration URI...');
        const url = new URL(uri);
        const data = url.searchParams.get('data');
        
        if (!data) {
            console.error('No data parameter found in migration URI');
            throw new Error('No data in migration QR code');
        }
        
        console.log('Found data parameter, length:', data.length);
        
        // Decode base64
        const decoded = atob(data);
        const bytes = new Uint8Array(decoded.length);
        for (let i = 0; i < decoded.length; i++) {
            bytes[i] = decoded.charCodeAt(i);
        }
        
        console.log('Decoded bytes:', bytes.length);
        
        // Parse the protobuf-like structure (simplified parser for TOTP accounts)
        const accounts = parseGoogleAuthProtobuf(bytes);
        
        console.log('Found accounts:', accounts.length);
        
        if (accounts.length === 0) {
            throw new Error('No TOTP accounts found in migration data');
        }
        
        // If multiple accounts, let user select
        if (accounts.length > 1) {
            console.log('Multiple accounts found, showing selection dialog');
            return selectAccountFromMultiple(accounts);
        }
        
        console.log('Successfully parsed account:', accounts[0].label || accounts[0].issuer);
        return accounts[0];
    } catch (error) {
        console.error('Migration parse error:', error);
        console.error('Migration URI:', uri);
        throw new Error('Failed to parse Google Authenticator export. Error: ' + error.message);
    }
}

// Simplified protobuf parser for Google Authenticator
function parseGoogleAuthProtobuf(bytes) {
    const accounts = [];
    let i = 0;
    
    while (i < bytes.length) {
        // Look for field tag 1 with wire type 2 (length-delimited)
        if (bytes[i] === 0x0A) {
            i++;
            const length = bytes[i];
            i++;
            
            const accountData = bytes.slice(i, i + length);
            const account = parseAccountData(accountData);
            if (account) {
                accounts.push(account);
            }
            i += length;
        } else {
            i++;
        }
    }
    
    return accounts;
}

// Parse individual account data from protobuf
function parseAccountData(data) {
    let secret = '';
    let name = '';
    let issuer = '';
    let i = 0;
    
    while (i < data.length) {
        const fieldTag = data[i];
        i++;
        
        if (fieldTag === 0x0A) { // Field 1: secret
            const length = data[i];
            i++;
            const secretBytes = data.slice(i, i + length);
            secret = base32Encode(secretBytes);
            i += length;
        } else if (fieldTag === 0x12) { // Field 2: name
            const length = data[i];
            i++;
            name = String.fromCharCode.apply(null, data.slice(i, i + length));
            i += length;
        } else if (fieldTag === 0x1A) { // Field 3: issuer
            const length = data[i];
            i++;
            issuer = String.fromCharCode.apply(null, data.slice(i, i + length));
            i += length;
        } else {
            // Skip unknown fields
            if (i < data.length) {
                const length = data[i];
                i += length + 1;
            }
        }
    }
    
    if (secret) {
        return {
            secret: secret,
            issuer: issuer,
            label: name
        };
    }
    
    return null;
}

// Base32 encoding for secret
function base32Encode(bytes) {
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    let bits = 0;
    let value = 0;
    let output = '';
    
    for (let i = 0; i < bytes.length; i++) {
        value = (value << 8) | bytes[i];
        bits += 8;
        
        while (bits >= 5) {
            output += alphabet[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    
    if (bits > 0) {
        output += alphabet[(value << (5 - bits)) & 31];
    }
    
    return output;
}

// Let user select from multiple accounts
function selectAccountFromMultiple(accounts) {
    const accountList = accounts.map((acc, idx) => {
        const displayName = acc.issuer ? `${acc.issuer} (${acc.label})` : acc.label;
        return `${idx + 1}. ${displayName}`;
    }).join('\n');
    
    const message = `Multiple accounts found in migration QR code:\n\n${accountList}\n\nThe first account will be imported. To import others, scan the QR code again for each account.`;
    alert(message);
    
    return accounts[0];
}

// Scan QR code from uploaded image
async function scanQRFromImage(imageFile) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        
        reader.onload = (e) => {
            const img = new Image();
            
            img.onload = () => {
                const canvas = document.createElement('canvas');
                const ctx = canvas.getContext('2d');
                
                canvas.width = img.width;
                canvas.height = img.height;
                ctx.drawImage(img, 0, 0);
                
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);
                
                if (code) {
                    try {
                        const totpData = parseTOTPUri(code.data);
                        resolve(totpData);
                    } catch (error) {
                        reject(error);
                    }
                } else {
                    reject(new Error('No QR code found in image'));
                }
            };
            
            img.onerror = () => reject(new Error('Failed to load image'));
            img.src = e.target.result;
        };
        
        reader.onerror = () => reject(new Error('Failed to read file'));
        reader.readAsDataURL(imageFile);
    });
}

// Start camera for QR scanning
async function startCameraScanning() {
    const modal = document.getElementById('camera-modal');
    const video = document.getElementById('camera-preview');
    const canvas = document.getElementById('qr-canvas');
    const statusDiv = document.getElementById('camera-status');
    
    modal.classList.remove('hidden');
    statusDiv.textContent = 'Starting camera...';
    statusDiv.className = 'camera-status';
    
    try {
        // Try environment camera first (back camera on phones), fallback to any camera
        let constraints = { video: { facingMode: 'environment' } };
        
        try {
            cameraStream = await navigator.mediaDevices.getUserMedia(constraints);
        } catch (err) {
            console.log('Environment camera failed, trying any camera:', err);
            // Fallback to any available camera (works better on desktop)
            constraints = { video: true };
            cameraStream = await navigator.mediaDevices.getUserMedia(constraints);
        }
        
        video.srcObject = cameraStream;
        
        // Wait for video to be ready
        await new Promise((resolve) => {
            video.onloadedmetadata = () => {
                video.play();
                resolve();
            };
        });
        
        statusDiv.textContent = 'Position QR code in view';
        
        // Start scanning loop
        scanningInterval = setInterval(() => {
            if (video.readyState === video.HAVE_ENOUGH_DATA) {
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
                
                const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
                const code = jsQR(imageData.data, imageData.width, imageData.height);
                
                if (code) {
                    try {
                        const totpData = parseTOTPUri(code.data);
                        
                        // Update the secret field
                        document.getElementById('totp-secret').value = totpData.secret;
                        
                        statusDiv.textContent = '✓ QR Code scanned successfully!';
                        statusDiv.className = 'camera-status success';
                        
                        // Close camera after 1 second
                        setTimeout(() => {
                            stopCameraScanning();
                        }, 1000);
                    } catch (error) {
                        console.error('Scan error:', error, 'Data:', code.data);
                        statusDiv.textContent = '⚠ ' + error.message;
                        statusDiv.className = 'camera-status error';
                        
                        // Clear error after 3 seconds to allow retry
                        setTimeout(() => {
                            if (statusDiv.className === 'camera-status error') {
                                statusDiv.textContent = 'Position QR code in view';
                                statusDiv.className = 'camera-status';
                            }
                        }, 3000);
                    }
                }
            }
        }, 100);
    } catch (error) {
        console.error('Camera error details:');
        console.error('Error name:', error.name);
        console.error('Error message:', error.message);
        console.error('Full error:', error);
        
        let errorMsg = '⚠ Camera access denied or unavailable';
        if (error.name === 'NotAllowedError' || error.message?.includes('Permission')) {
            errorMsg = '⚠ Camera permission denied. Click the 🔒 icon in address bar to allow camera.';
        } else if (error.name === 'NotFoundError' || error.message?.includes('not found')) {
            errorMsg = '⚠ No camera found. Please use "Upload QR Code" instead.';
        } else if (error.name === 'NotReadableError' || error.message?.includes('Could not start')) {
            errorMsg = '⚠ Camera in use by another app. Close other apps and try again.';
        } else if (error.name === 'OverconstrainedError') {
            errorMsg = '⚠ Camera constraints not met. Trying simpler settings...';
            // Try one more time with minimal constraints
            try {
                cameraStream = await navigator.mediaDevices.getUserMedia({ video: { width: 640 } });
                video.srcObject = cameraStream;
                statusDiv.textContent = 'Position QR code in view';
                return; // Exit the catch block if successful
            } catch (retryError) {
                errorMsg = '⚠ Camera not compatible. Use "Upload QR Code" instead.';
            }
        } else {
            errorMsg = `⚠ Camera error: ${error.message || 'Unknown error'}. Try "Upload QR Code".`;
        }
        
        statusDiv.textContent = errorMsg;
        statusDiv.className = 'camera-status error';
        
        setTimeout(() => {
            stopCameraScanning();
        }, 5000);
    }
}

// Stop camera scanning
function stopCameraScanning() {
    if (scanningInterval) {
        clearInterval(scanningInterval);
        scanningInterval = null;
    }
    
    if (cameraStream) {
        cameraStream.getTracks().forEach(track => track.stop());
        cameraStream = null;
    }
    
    const modal = document.getElementById('camera-modal');
    const video = document.getElementById('camera-preview');
    video.srcObject = null;
    modal.classList.add('hidden');
}

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
    const password = document.getElementById('password').value;
    const copyFormat = document.querySelector('.format-btn.active').dataset.format;
    
    if (!totpSecret || !password) {
        alert('Please enter TOTP secret and password');
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
    localStorage.setItem('vpn_password', password);
    localStorage.setItem('vpn_copy_format', copyFormat);
    
    // Update display
    updateCredentialsDisplay();
    
    // Hide settings automatically after save
    const settingsSection = document.getElementById('settings-section');
    const toggleBtn = document.getElementById('toggle-settings');
    settingsSection.classList.add('hidden');
    toggleBtn.textContent = 'Settings';
    
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
function loadSettings(populateFields = true) {
    const totpSecret = localStorage.getItem('vpn_totp_secret') || '';
    const timeOffset = parseInt(localStorage.getItem('vpn_time_offset')) || 0;
    const password = localStorage.getItem('vpn_password') || '';
    const copyFormat = localStorage.getItem('vpn_copy_format') || 'totp-first';
    
    // Only populate fields if requested and they exist in the DOM
    if (populateFields) {
        const totpField = document.getElementById('totp-secret');
        const timeOffsetField = document.getElementById('time-offset');
        const passwordField = document.getElementById('password');
        
        if (totpField) totpField.value = totpSecret;
        if (timeOffsetField) timeOffsetField.value = timeOffset;
        if (passwordField) passwordField.value = password;
        
        // Set format buttons
        document.querySelectorAll('.format-btn').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.format === copyFormat) {
                btn.classList.add('active');
            }
        });
    }
    
    return { totpSecret, timeOffset, password, copyFormat };
}

// Update credentials display
async function updateCredentialsDisplay() {
    const settings = loadSettings(false); // Don't populate fields, just get values
    
    // Check if all required settings are present
    if (!settings.totpSecret || !settings.password) {
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
            toggleBtn.textContent = '✕ Close';
        } else {
            settingsSection.classList.add('hidden');
            toggleBtn.textContent = '⚙️ Settings';
        }
    });
    
    // Set up QR code upload button
    document.getElementById('scan-qr-upload').addEventListener('click', () => {
        document.getElementById('qr-file-input').click();
    });
    
    // Handle file upload
    document.getElementById('qr-file-input').addEventListener('change', async (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const uploadBtn = document.getElementById('scan-qr-upload');
        const originalText = uploadBtn.textContent;
        
        try {
            uploadBtn.textContent = '⏳ Scanning...';
            uploadBtn.disabled = true;
            
            const totpData = await scanQRFromImage(file);
            
            // Update the secret field
            document.getElementById('totp-secret').value = totpData.secret;
            
            uploadBtn.textContent = '✓ Scanned!';
            uploadBtn.style.background = '#198754';
            uploadBtn.style.color = 'white';
            
            setTimeout(() => {
                uploadBtn.textContent = originalText;
                uploadBtn.style.background = '';
                uploadBtn.style.color = '';
                uploadBtn.disabled = false;
            }, 2000);
        } catch (error) {
            uploadBtn.textContent = '✗ Failed';
            uploadBtn.style.background = '#dc3545';
            uploadBtn.style.color = 'white';
            
            alert(error.message || 'Failed to scan QR code from image');
            
            setTimeout(() => {
                uploadBtn.textContent = originalText;
                uploadBtn.style.background = '';
                uploadBtn.style.color = '';
                uploadBtn.disabled = false;
            }, 2000);
        }
        
        // Reset file input
        e.target.value = '';
    });
    
    // Set up QR code camera button
    document.getElementById('scan-qr-camera').addEventListener('click', () => {
        startCameraScanning();
    });
    
    // Set up close camera button
    document.getElementById('close-camera').addEventListener('click', () => {
        stopCameraScanning();
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
        const settings = loadSettings(false); // Don't populate fields, just get values
        
        if (!settings.totpSecret || !settings.password) {
            alert('Please configure all settings first:\n1. Enter your TOTP secret key\n2. Enter your password');
            // Show settings if they're hidden
            const settingsSection = document.getElementById('settings-section');
            const toggleBtn = document.getElementById('toggle-settings');
            if (settingsSection.classList.contains('hidden')) {
                settingsSection.classList.remove('hidden');
                toggleBtn.textContent = '✕ Close';
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
    
    document.getElementById('password').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') saveSettings();
    });
    
    // Update display every second for countdown
    setInterval(async () => {
        const timeRemaining = getTimeRemaining();
        const countdownElement = document.getElementById('countdown');
        countdownElement.textContent = timeRemaining;
        
        // Add urgent class when time is low
        if (timeRemaining <= 5) {
            countdownElement.classList.add('urgent');
        } else {
            countdownElement.classList.remove('urgent');
        }
        
        // Regenerate TOTP when it expires
        if (timeRemaining === 30 || timeRemaining === 29) {
            await updateCredentialsDisplay();
        }
    }, 1000);
});

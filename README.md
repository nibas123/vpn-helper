#   VPN TOTP Helper - Chrome Extension

A simple Chrome extension that generates TOTP codes for   VPN authentication and copies the TOTP+password combination to clipboard with one click.

## Features

- 🔐 **Auto-generates TOTP** for VPN using hardcoded secret key
- ⚙️ **User settings** - Enter your own username and password
- 📋 **One-click copy** - Copies TOTP+password combination to clipboard
- ⏱️ **Real-time countdown** showing when TOTP expires
- 🔄 **Auto-refresh** every 30 seconds
- 💾 **Secure storage** - Settings saved locally in your browser
- 🎨 **Clean, modern UI** with visual feedback
- 🚀 **No internet required** - works completely offline

## How to Install

1. **Download the extension folder** (`chrome-extension`)
2. **Open Chrome** and go to `chrome://extensions/`
3. **Enable Developer mode** (toggle in top-right)
4. **Click "Load unpacked"** and select the `chrome-extension` folder
5. **Pin the extension** to your toolbar for easy access

## How to Use

### First Time Setup:
1. Click the extension icon in Chrome toolbar
2. Enter your **username** and **password** in the Settings section
3. Click **"💾 Save Settings"**

### Daily Usage:
1. Click the extension icon
2. Click **"📋 Copy TOTP+Password"**
3. Paste into OpenVPN GUI password field (Ctrl+V)

## What Gets Copied

The extension copies the **TOTP+Password combination** directly:

Example: `123456nibas@123`
- `123456` = Current TOTP code
- `nibas@123` = Your saved password

This is exactly what   VPN expects in the password field.

## Security Notes

- ✅ **TOTP secret is hardcoded** - no need to enter it
- ✅ **Local storage only** - your password never leaves your browser
- ✅ **No external connections** - everything runs locally
- ✅ **Same algorithm** - TOTP matches your phone's authenticator app
- ✅ **Auto-clear clipboard** - consider clearing clipboard after use

## Troubleshooting

**TOTP doesn't match phone:**
- The extension uses the same -30 second adjustment that was tested
- Ensure your computer's time is correct

**Copy button disabled:**
- Make sure you've entered and saved both username and password
- Check that TOTP is generating (not showing "ERROR")

**Settings not saving:**
- Ensure Chrome has permission to store local data
- Try reloading the extension

---

**Perfect for:** Quick   VPN connections without manually typing TOTP codes! 🚀

## How to Install

1. **Download the extension folder** (`chrome-extension`)
2. **Open Chrome** and go to `chrome://extensions/`
3. **Enable Developer mode** (toggle in top-right)
4. **Click "Load unpacked"** and select the `chrome-extension` folder
5. **Pin the extension** to your toolbar for easy access

## How to Use

### For   VPN:
1. Click the extension icon in Chrome toolbar
2. Click **"📋 Copy   Credentials"**
3. Paste into OpenVPN GUI (Ctrl+V)
   - Username will be on first line
   - TOTP+Password will be on second line

### For IXM VPN:
1. Click the extension icon
2. Click **"📋 Copy IXM Credentials"**
3. Paste into OpenVPN GUI

## What Gets Copied


## Security Notes

- ✅ All processing happens locally in your browser
- ✅ No data is sent to any external servers
- ✅ Credentials are hardcoded in the extension (not stored)
- ✅ TOTP algorithm matches your phone's authenticator app

## Troubleshooting

**TOTP doesn't match phone:**
- The extension uses a -30 second time adjustment that was tested to match your phone
- If it still doesn't match, check your computer's time is correct

**Copy doesn't work:**
- Make sure you're clicking the copy button (not just the text)
- Chrome requires user interaction to access clipboard

**Extension not loading:**
- Make sure all files are in the same folder
- Check Chrome's extension page for error messages
- Try reloading the extension

## Files Structure

```
chrome-extension/
├── manifest.json     # Extension configuration
├── popup.html        # UI layout
├── popup.js          # TOTP generation logic
├── icon.svg          # Extension icon
└── README.md         # This file
```

## Advanced Usage

You can modify the credentials by editing `popup.js`:
- Change usernames/passwords in the constants at the top
- Modify the TOTP secret if needed
- Adjust time sync offset if TOTP doesn't match

---

**Perfect for:** Quick VPN connections without typing long TOTP+password combinations! 🚀

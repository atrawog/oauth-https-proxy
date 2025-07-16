# Merged Tabs Update

## Overview

The MCP Proxy Manager web GUI has been updated to merge related tabs for a cleaner, more intuitive interface.

## Changes Made

### 1. HTML Structure (`index.html`)
- **Removed tabs**: "New Certificate" and "New Proxy Target" 
- **Merged functionality** into "Certificates" and "Proxies" tabs
- **Added** "Add Certificate" and "Add Proxy" buttons in tab headers
- **Added** collapsible form containers within each tab
- **Added** Cancel buttons to forms

### 2. CSS Styling (`styles.css`)
- **Added** `.tab-header` class for title + button layout
- **Added** `.form-container` class for collapsible forms
- **Added** `.form-actions` class for form button groups
- **Added** `input[type="url"]` styling
- **Updated** responsive design considerations

### 3. JavaScript Logic (`app.js`)
- **Added** `toggleCertificateForm()` and `toggleProxyForm()` functions
- **Added** `hideCertificateForm()` and `hideProxyForm()` functions
- **Updated** `switchTab()` to hide forms when switching tabs
- **Updated** tab name from 'proxy' to 'proxies'
- **Updated** form submission handlers to hide forms after success
- **Added** event listeners for Add buttons

## User Experience

### Before (5 tabs)
1. Certificates
2. New Certificate  
3. Proxy Targets
4. New Proxy Target
5. Settings

### After (3 tabs)
1. **Certificates** - List + Add functionality
2. **Proxies** - List + Add functionality  
3. **Settings** - Email configuration

## How It Works

1. User clicks on "Certificates" or "Proxies" tab
2. Sees list of existing items
3. Clicks "Add Certificate" or "Add Proxy" button
4. Form slides down below the button
5. Button changes to "Cancel" 
6. User fills form and submits or cancels
7. Form hides and list refreshes

## Benefits

- **50% fewer tabs** (5 → 3)
- **Related functionality grouped** together
- **Cleaner interface** with less clutter
- **More intuitive** - view and create in same place
- **Better UX** - less context switching

## Testing

Run `just test-merged-tabs` to verify:
- New tab structure is present
- Old tabs are removed
- Add buttons exist
- Toggle functions work
- CSS classes are loaded
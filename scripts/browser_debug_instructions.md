# Browser Debug Instructions for GUI Issues

## The Problem
The web GUI at https://gui.atradev.org/ isn't showing certificates, proxies, or routes even though:
- ✅ The API endpoints are working correctly
- ✅ The JavaScript code is correct
- ✅ The proxy configuration is correct
- ✅ The backend returns all data correctly

## Root Cause Analysis Results

### 1. Backend API - WORKING ✅
- GET /certificates returns 4 certificates
- GET /proxy/targets returns 5 proxies  
- GET /routes returns 4 routes
- All endpoints work correctly with ADMIN token

### 2. Frontend Code - CORRECT ✅
- app.js contains all necessary functions
- Ownership filtering code is present
- DOM update logic is correct

### 3. Proxy Configuration - CORRECT ✅
- gui.atradev.org proxies to localhost:80
- route_mode is "all" (forwards all routes)
- Both HTTP and HTTPS are enabled

## The Issue Must Be Browser-Side

Please follow these steps to debug:

### Step 1: Clear Browser Cache
1. Hard refresh: `Ctrl+Shift+R` (Windows/Linux) or `Cmd+Shift+R` (Mac)
2. Or clear all browser data for gui.atradev.org

### Step 2: Open Browser DevTools
1. Go to https://gui.atradev.org/
2. Press `F12` to open DevTools
3. Click on the "Console" tab

### Step 3: Check for JavaScript Errors
Look for any red error messages in the console. Common errors:
- `Uncaught TypeError`
- `Cannot read property`
- `Failed to fetch`

### Step 4: Test Login
1. Enter the ADMIN token: `acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us`
2. Click Login
3. Check if the header shows "Authenticated as: ADMIN"

### Step 5: Test API Directly in Console
After logging in, paste these commands in the console:

```javascript
// Test 1: Check if API client exists
console.log('API client exists:', typeof api);

// Test 2: Get certificates
api.getCertificates().then(certs => {
    console.log('Certificates:', certs);
    console.log('Count:', certs.length);
}).catch(err => console.error('Error:', err));

// Test 3: Check current token info
console.log('Current token info:', currentTokenInfo);

// Test 4: Check if certificates list element exists
console.log('Certificates list element:', document.getElementById('certificates-list'));

// Test 5: Manually trigger load
loadCertificates();
```

### Step 6: Check Network Tab
1. Click on "Network" tab in DevTools
2. Refresh the page
3. Look for failed requests (red)
4. Check if /certificates, /proxy/targets, /routes requests succeed

### Step 7: Report Results
Please share:
1. Any error messages from the Console
2. Results of the test commands
3. Any failed network requests
4. What exactly you see on screen (screenshot if possible)

## Possible Causes
1. **JavaScript Error**: Code fails before updating DOM
2. **Race Condition**: Code runs before DOM is ready  
3. **Browser Extension**: Ad blocker or security extension interfering
4. **CORS Issue**: Browser blocking cross-origin requests
5. **Old Cached JavaScript**: Browser using old version without fixes

## Quick Fix Attempts
1. Try a different browser (Chrome, Firefox, Edge)
2. Try incognito/private mode
3. Disable browser extensions temporarily
4. Check if you're behind a corporate proxy
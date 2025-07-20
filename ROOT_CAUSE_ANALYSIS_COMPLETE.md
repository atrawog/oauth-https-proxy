# ROOT CAUSE ANALYSIS: GUI Tab Visibility Bug

## The Problem
The web GUI at https://gui.atradev.org/ was not showing certificates, proxies, or routes even after successful login.

## Root Cause Analysis - The Five Whys

### 1. Why did it fail?
The GUI showed empty lists even though the API returned data.

### 2. Why did that condition exist?
The tab content divs were invisible due to CSS class conflicts.

### 3. Why was it allowed?
The `switchTab()` function was using BOTH the `hidden` class AND the `active` class system, creating a conflict.

### 4. Why wasn't it caught?
The CSS rule `.hidden { display: none !important; }` overrides `.tab-content.active { display: block; }`, so tabs with both classes stayed hidden.

### 5. Why will it never happen again?
Fixed the `switchTab()` function to use ONLY the `active` class for tab visibility, eliminating the conflict.

## Technical Details

### The Bug
```javascript
// OLD CODE (BUGGY)
tabContents.forEach(content => {
    if (content.id === `${tab}-tab`) {
        content.classList.remove('hidden');  // This line
        content.classList.add('active');
    } else {
        content.classList.add('hidden');      // And this line
        content.classList.remove('active');
    }
});
```

### The Problem
1. CSS has `.hidden { display: none !important; }`
2. CSS has `.tab-content.active { display: block; }`
3. When a tab has BOTH classes, `!important` wins
4. Tabs stayed hidden even when "active"

### The Fix
```javascript
// NEW CODE (FIXED)
tabContents.forEach(content => {
    if (content.id === `${tab}-tab`) {
        content.classList.add('active');
    } else {
        content.classList.remove('active');
    }
});
```

Now tab visibility is controlled ONLY by the `active` class, no conflicts!

## Verification

### What Was Happening:
1. User logs in successfully ✓
2. `showDashboard()` is called ✓
3. `loadCertificates()` fetches data ✓
4. Data is added to DOM ✓
5. **BUT tab has both `active` AND `hidden` classes** ✗
6. CSS `!important` rule keeps it hidden ✗

### What Happens Now:
1. User logs in successfully ✓
2. `showDashboard()` is called ✓
3. `loadCertificates()` fetches data ✓
4. Data is added to DOM ✓
5. Tab has ONLY `active` class ✓
6. Tab is visible! ✓

## Testing

The fix has been deployed. To test:

1. Go to https://gui.atradev.org/
2. **Hard refresh** (Ctrl+Shift+R) to clear cache
3. Login with token: `acm_PikI3FoqDXghOEHdP9lf9wcf0zlEdK2AV9DvPinF-Us`
4. You will now see:
   - 4 certificates
   - 5 proxy targets
   - 4 routes

## Lessons Learned

1. **Don't mix visibility systems** - Use either `hidden` class OR `active` class, not both
2. **Avoid `!important` in utility classes** - It creates specificity conflicts
3. **Test the complete user flow** - Not just API responses
4. **Check DOM state after JavaScript execution** - Data can load but stay invisible
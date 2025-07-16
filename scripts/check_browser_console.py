#!/usr/bin/env python3
"""Simple script to guide manual browser console checking."""

print("""
=================================================================
BROWSER CONSOLE DEBUG INSTRUCTIONS
=================================================================

Please open your web browser and follow these steps:

1. Navigate to: http://localhost:80

2. Open Browser Developer Tools:
   - Chrome/Edge: Press F12 or Ctrl+Shift+I (Cmd+Option+I on Mac)
   - Firefox: Press F12 or Ctrl+Shift+I (Cmd+Option+I on Mac)
   - Safari: Enable Developer menu in Preferences, then Cmd+Option+I

3. Click on the "Console" tab in Developer Tools

4. Login with this test token:
   acm_e5AGpHJd2qxWocqBn6lXDBV_6AvD02R-A6AhdmSK8uA

5. After logging in, click the "Settings" tab

6. Look for these debug messages in the console:
   - [DEBUG] loadTokenInfo called
   - [DEBUG] api.token: <token value>
   - [DEBUG] Making request to /token/info
   - [DEBUG] Response OK/not OK

7. Check for any error messages or null values

8. You can also manually test in the console:
   > api.token  // Should show your token
   > loadTokenInfo()  // Manually trigger the function

Please report what you see in the console!
=================================================================
""")
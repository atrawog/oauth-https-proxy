#!/usr/bin/env python3
"""Test JavaScript token handling."""

import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options

def test_js_token():
    """Test JavaScript token handling in browser."""
    print("\n" + "="*60)
    print("Testing JavaScript Token Handling")
    print("="*60 + "\n")
    
    # Setup headless Chrome
    options = Options()
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')
    
    driver = webdriver.Chrome(options=options)
    
    try:
        # Navigate to the page
        driver.get("http://localhost:80")
        print("✅ Page loaded")
        
        # Check localStorage
        token_in_storage = driver.execute_script("return localStorage.getItem('bearer_token');")
        print(f"Token in localStorage: {token_in_storage[:20] if token_in_storage else 'None'}...")
        
        # Check api.token
        api_token = driver.execute_script("return api.token;")
        print(f"api.token value: {api_token[:20] if api_token else 'None'}...")
        
        # Login with test token
        token = "acm_e5AGpHJd2qxWocqBn6lXDBV_6AvD02R-A6AhdmSK8uA"
        driver.find_element(By.ID, "token").send_keys(token)
        driver.find_element(By.CSS_SELECTOR, "form#login-form button[type='submit']").click()
        
        # Wait for dashboard
        time.sleep(2)
        
        # Check token after login
        token_after = driver.execute_script("return api.token;")
        print(f"\nAfter login - api.token: {token_after[:20] if token_after else 'None'}...")
        
        # Click Settings tab
        driver.find_element(By.CSS_SELECTOR, "button[data-tab='settings']").click()
        time.sleep(1)
        
        # Check console errors
        console_logs = driver.get_log('browser')
        if console_logs:
            print("\nConsole logs:")
            for log in console_logs:
                if 'SEVERE' in log['level']:
                    print(f"  ❌ {log['message']}")
        
        # Check if loadTokenInfo was called
        result = driver.execute_script("""
            // Manually call loadTokenInfo and check
            console.log('api.token:', api.token);
            console.log('Calling loadTokenInfo...');
            loadTokenInfo();
            return api.token;
        """)
        print(f"\nManual loadTokenInfo test - api.token: {result[:20] if result else 'None'}...")
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
    finally:
        driver.quit()
    
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    test_js_token()
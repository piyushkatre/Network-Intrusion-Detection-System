import os
import time
import subprocess
import urllib.request
from playwright.sync_api import sync_playwright

def wait_for_server():
    for _ in range(90):
        try:
            urllib.request.urlopen("http://127.0.0.1:5000")
            return True
        except:
            time.sleep(1)
    return False

def main():
    print("Starting Flask server...")
    server = subprocess.Popen(["python", "src/app.py"])
    
    print("Waiting for server to start...")
    if not wait_for_server():
        print("Server did not start in time.")
        server.terminate()
        return

    print("Server is up!")
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(args=['--window-size=1920,1080'])
            page = browser.new_page(viewport={'width': 1920, 'height': 1080}, color_scheme='dark')
            
            print("Navigating to dashboard...")
            page.goto("http://127.0.0.1:5000/blockchain", wait_until="networkidle", timeout=60000)
            
            # Additional wait for all charts and data to visually populate
            time.sleep(8)
            
            print("Taking screenshot...")
            page.screenshot(path="dashboard.png", full_page=False) # Capture just the viewport
            print("Screenshot saved to dashboard.png")
            browser.close()
    finally:
        print("Stopping server...")
        server.terminate()

if __name__ == "__main__":
    main()

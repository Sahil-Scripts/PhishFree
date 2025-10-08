from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    print("playwright OK, chromium available:", hasattr(p.chromium, "launch"))

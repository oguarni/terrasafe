import pytest
import threading
import time
import uvicorn

# Skip the entire module if playwright is not installed
playwright = pytest.importorskip("playwright.sync_api")
from playwright.sync_api import Page, expect

from terravault.api import app

@pytest.fixture(scope="module")
def server():
    """Runs the FastAPI server in a background thread for testing."""
    config = uvicorn.Config(app=app, host="127.0.0.1", port=8081, log_level="error")
    server = uvicorn.Server(config=config)
    
    thread = threading.Thread(target=server.run)
    thread.daemon = True
    thread.start()
    
    # Wait for server to be ready
    time.sleep(2)
    
    yield "http://127.0.0.1:8081"
    
    server.should_exit = True
    thread.join(timeout=2)

def test_dashboard_loads(page: Page, server: str):
    """Test that the dashboard loads correctly."""
    page.goto(server)
    expect(page).to_have_title("TerraVault | Security Dashboard")
    expect(page.locator("h1")).to_have_text("Security Overview")
    
    # Check that navigation excludes 'History'
    nav_text = page.locator("nav").inner_text()
    assert "History" not in nav_text
    assert "Dashboard" in nav_text
    assert "Scan" in nav_text

def test_navigation_to_scan(page: Page, server: str):
    """Test navigation from dashboard to scan page."""
    page.goto(server)
    page.get_by_role("link", name="Scan").click()
    expect(page.locator("h1")).to_have_text("Security Scan")
    expect(page.get_by_text("INITIATE SECURITY SCAN")).to_be_visible()

def test_settings_saving(page: Page, server: str):
    """Test that settings auto-save to localStorage."""
    page.goto(f"{server}/settings.html")
    expect(page.locator("h1")).to_have_text("Settings & Configuration")
    
    # Fill in the API Key
    api_key_input = page.locator("#api-key")
    api_key_input.fill("test-api-key-1234")
    
    # The frontend uses 'input' event to save automatically
    page.wait_for_timeout(500)
    
    # Reload the page and verify persistence
    page.reload()
    expect(page.locator("#api-key")).to_have_value("test-api-key-1234")

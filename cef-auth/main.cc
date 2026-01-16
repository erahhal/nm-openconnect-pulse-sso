// Minimal CEF application for Pulse VPN SSO authentication
// Navigates to VPN URL, waits for DSID cookie, outputs it and exits

#include <iostream>
#include <string>
#include <cstring>
#include <chrono>

#include "include/cef_app.h"
#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "include/cef_command_line.h"
#include "include/cef_cookie.h"
#include "include/cef_request_handler.h"
#include "include/cef_resource_request_handler.h"
#include "include/cef_task.h"
#include "include/internal/cef_types.h"
#include "include/wrapper/cef_helpers.h"

// Global state
std::string g_vpn_url;
std::string g_dsid_cookie;
std::string g_extension_path;
bool g_found_cookie = false;
bool g_should_close = false;
int g_timeout_seconds = 300;
std::chrono::steady_clock::time_point g_start_time;
CefRefPtr<CefBrowser> g_browser;

// User agent switching state (for Okta bypass)
// Start with Windows UA to bypass Okta's Linux blocking, then switch to Linux UA after first load
std::string g_windows_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
std::string g_linux_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36";
bool g_first_load_complete = false;
bool g_ua_switched = false;

// Forward declarations
void ScheduleCookieCheck();
void CheckAndCloseBrowser();

// Resource request handler to modify User-Agent header per request
class AuthResourceRequestHandler : public CefResourceRequestHandler {
public:
    cef_return_value_t OnBeforeResourceLoad(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefRequest> request,
        CefRefPtr<CefCallback> callback) override {

        CefRequest::HeaderMap headers;
        request->GetHeaderMap(headers);

        // Remove existing User-Agent header
        auto it = headers.find("User-Agent");
        if (it != headers.end()) {
            headers.erase(it);
        }

        // Use Windows UA for first load, Linux UA after switch
        if (g_ua_switched) {
            headers.insert(std::make_pair("User-Agent", g_linux_ua));
        } else {
            headers.insert(std::make_pair("User-Agent", g_windows_ua));
        }

        request->SetHeaderMap(headers);
        return RV_CONTINUE;
    }

private:
    IMPLEMENT_REFCOUNTING(AuthResourceRequestHandler);
};

// Client handler
class AuthClient : public CefClient,
                   public CefLifeSpanHandler,
                   public CefLoadHandler,
                   public CefRequestHandler {
public:
    AuthClient() : resource_handler_(new AuthResourceRequestHandler()) {}

    CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
    CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }
    CefRefPtr<CefRequestHandler> GetRequestHandler() override { return this; }

    // CefRequestHandler - return our resource handler for all requests
    CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefRequest> request,
        bool is_navigation,
        bool is_download,
        const CefString& request_initiator,
        bool& disable_default_handling) override {
        return resource_handler_;
    }

    // CefLifeSpanHandler
    void OnAfterCreated(CefRefPtr<CefBrowser> browser) override {
        CEF_REQUIRE_UI_THREAD();
        if (!g_browser) {
            g_browser = browser;
        }
    }

    // Block all popups and new tabs
    bool OnBeforePopup(CefRefPtr<CefBrowser> browser,
                       CefRefPtr<CefFrame> frame,
                       int popup_id,
                       const CefString& target_url,
                       const CefString& target_frame_name,
                       CefLifeSpanHandler::WindowOpenDisposition target_disposition,
                       bool user_gesture,
                       const CefPopupFeatures& popupFeatures,
                       CefWindowInfo& windowInfo,
                       CefRefPtr<CefClient>& client,
                       CefBrowserSettings& settings,
                       CefRefPtr<CefDictionaryValue>& extra_info,
                       bool* no_javascript_access) override {
        // Return true to cancel the popup/new tab
        return true;
    }

    void OnBeforeClose(CefRefPtr<CefBrowser> browser) override {
        CEF_REQUIRE_UI_THREAD();
        g_browser = nullptr;
        CefQuitMessageLoop();
    }

    // CefLoadHandler - handle UA switching and cookie checking after page load
    void OnLoadEnd(CefRefPtr<CefBrowser> browser,
                   CefRefPtr<CefFrame> frame,
                   int httpStatusCode) override {
        if (frame->IsMain() && !g_found_cookie) {
            if (!g_first_load_complete) {
                // First load complete with Windows UA - now switch to Linux UA and reload
                // This bypasses Okta's initial Linux blocking while ensuring proper behavior after
                g_first_load_complete = true;
                g_ua_switched = true;
                std::cerr << "Switching to Linux user agent and reloading..." << std::endl;
                browser->Reload();
            } else {
                // Subsequent loads - check for DSID cookie
                CheckAndCloseBrowser();
            }
        }
    }

private:
    CefRefPtr<AuthResourceRequestHandler> resource_handler_;
    IMPLEMENT_REFCOUNTING(AuthClient);
};

CefRefPtr<AuthClient> g_client;

// Task to close the browser
class CloseBrowserTask : public CefTask {
public:
    void Execute() override {
        if (g_browser) {
            g_browser->GetHost()->CloseBrowser(true);
        }
    }
private:
    IMPLEMENT_REFCOUNTING(CloseBrowserTask);
};

// Cookie visitor to find DSID
class DSIDCookieVisitor : public CefCookieVisitor {
public:
    bool Visit(const CefCookie& cookie, int count, int total, bool& deleteCookie) override {
        std::string name = CefString(&cookie.name).ToString();
        if (name == "DSID") {
            g_dsid_cookie = CefString(&cookie.value).ToString();
            g_found_cookie = true;
            // Close browser - OnBeforeClose will quit the message loop
            CefPostTask(TID_UI, new CloseBrowserTask());
            return false; // Stop visiting
        }
        return true; // Continue
    }

private:
    IMPLEMENT_REFCOUNTING(DSIDCookieVisitor);
};

// Check for cookie and close browser if found/timeout
void CheckAndCloseBrowser() {
    if (g_found_cookie || g_should_close) return;

    // Check timeout
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - g_start_time);
    if (elapsed.count() >= g_timeout_seconds) {
        std::cerr << "Timeout waiting for authentication" << std::endl;
        g_should_close = true;
        if (g_browser) {
            g_browser->GetHost()->CloseBrowser(true);
        }
        return;
    }

    // Check for cookie
    CefRefPtr<CefCookieManager> manager = CefCookieManager::GetGlobalManager(nullptr);
    if (manager) {
        CefRefPtr<DSIDCookieVisitor> visitor = new DSIDCookieVisitor();
        manager->VisitUrlCookies(g_vpn_url, true, visitor);
    }
}

// Task to check cookies periodically
class CookieCheckTask : public CefTask {
public:
    void Execute() override {
        if (g_found_cookie || g_should_close) return;

        CheckAndCloseBrowser();

        // Schedule next check (500ms)
        if (!g_found_cookie && !g_should_close) {
            CefPostDelayedTask(TID_UI, new CookieCheckTask(), 500);
        }
    }
private:
    IMPLEMENT_REFCOUNTING(CookieCheckTask);
};

void ScheduleCookieCheck() {
    CefPostDelayedTask(TID_UI, new CookieCheckTask(), 500);
}

// Application handler
class AuthApp : public CefApp, public CefBrowserProcessHandler {
public:
    CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override {
        return this;
    }

    // Add command-line switches before CEF processes them
    void OnBeforeCommandLineProcessing(
        const CefString& process_type,
        CefRefPtr<CefCommandLine> command_line) override {

        // Only modify for browser process (empty process_type)
        if (process_type.empty()) {
            // Enable WebAuthentication
            command_line->AppendSwitch("enable-web-authentication");

            // Disable sandbox for USB access (WebAuthn)
            command_line->AppendSwitch("no-sandbox");
            command_line->AppendSwitch("disable-setuid-sandbox");

            // Enable features: WebAuthn + GPU acceleration
            command_line->AppendSwitchWithValue("enable-features",
                "WebAuthentication,WebAuthenticationConditionalUI,"
                "Vulkan,SkiaRenderer,CanvasOopRasterization");

            // GPU acceleration
            command_line->AppendSwitch("ignore-gpu-blocklist");
            command_line->AppendSwitch("enable-gpu-rasterization");
            command_line->AppendSwitch("enable-oop-rasterization");
            command_line->AppendSwitch("enable-zero-copy");

            // Use native OpenGL on Linux
            command_line->AppendSwitchWithValue("use-gl", "desktop");

            // Disable software compositing fallback
            command_line->AppendSwitch("disable-software-rasterizer");

            // Set unique app-id for window managers (Wayland app_id / X11 WM_CLASS)
            command_line->AppendSwitchWithValue("class", "pulse-vpn-auth");

            // Load extension if specified
            if (!g_extension_path.empty()) {
                command_line->AppendSwitchWithValue("load-extension", g_extension_path);
            }
        }
    }

    void OnContextInitialized() override {
        CEF_REQUIRE_UI_THREAD();

        CefWindowInfo window_info;
        // Set window title and size for top-level window
        CefString(&window_info.window_name) = "Pulse VPN Authentication";
        window_info.bounds.x = 200;
        window_info.bounds.y = 150;
        window_info.bounds.width = 800;
        window_info.bounds.height = 600;

        // Use Chrome runtime style for WebAuthn/FIDO2 support
        // Alloy style doesn't have native WebAuthn dialog support
        window_info.runtime_style = CEF_RUNTIME_STYLE_CHROME;

        CefBrowserSettings browser_settings;

        g_client = new AuthClient();
        CefBrowserHost::CreateBrowser(window_info, g_client, g_vpn_url,
                                       browser_settings, nullptr, nullptr);

        // Start periodic cookie checking
        ScheduleCookieCheck();
    }

private:
    IMPLEMENT_REFCOUNTING(AuthApp);
};

void PrintUsage(const char* program) {
    std::cerr << "Usage: " << program << " --url <vpn-url> [--timeout <seconds>] [--extension <path>]" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Opens a browser window, waits for DSID cookie, outputs it." << std::endl;
    std::cerr << "Output format: DSID=<cookie-value>" << std::endl;
    std::cerr << std::endl;
    std::cerr << "Options:" << std::endl;
    std::cerr << "  --extension <path>  Load unpacked Chrome extension from directory" << std::endl;
}

int main(int argc, char* argv[]) {
    // CEF initialization - MUST be done first for subprocess handling
    CefMainArgs main_args(argc, argv);
    CefRefPtr<AuthApp> app = new AuthApp();

    // Execute subprocess if this is a CEF helper process
    // This returns >= 0 for subprocesses and < 0 for the main process
    int exit_code = CefExecuteProcess(main_args, app, nullptr);
    if (exit_code >= 0) {
        // This is a subprocess, exit with CEF's return code
        return exit_code;
    }

    // This is the main browser process - now parse our arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            g_vpn_url = argv[++i];
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc) {
            g_timeout_seconds = std::stoi(argv[++i]);
        } else if (strcmp(argv[i], "--extension") == 0 && i + 1 < argc) {
            g_extension_path = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        }
        // Ignore CEF's internal arguments (--type=, etc.)
    }

    if (g_vpn_url.empty()) {
        PrintUsage(argv[0]);
        return 1;
    }

    // Record start time for timeout
    g_start_time = std::chrono::steady_clock::now();

    // CEF settings
    CefSettings settings;
    settings.no_sandbox = true;
    settings.windowless_rendering_enabled = false;

    // Set initial user agent to Windows for Okta bypass
    // OnBeforeResourceLoad will dynamically switch to Linux UA after first page load
    CefString(&settings.user_agent) = g_windows_ua;

    // Set cache path for persistent cookies/sessions
    std::string cache_path = std::string(getenv("HOME") ? getenv("HOME") : "/tmp") + "/.cache/pulse-browser-auth";
    CefString(&settings.root_cache_path) = cache_path;
    CefString(&settings.cache_path) = cache_path;

    if (!CefInitialize(main_args, settings, app, nullptr)) {
        std::cerr << "CEF initialization failed" << std::endl;
        return 1;
    }

    // Run the CEF message loop - this is the proper way
    // It handles all events efficiently and returns when CefQuitMessageLoop() is called
    CefRunMessageLoop();

    // Output the cookie if found
    if (g_found_cookie) {
        std::cout << "DSID=" << g_dsid_cookie << std::endl;
    }

    // Cleanup - browser is already closed at this point
    g_client = nullptr;
    CefShutdown();

    return g_found_cookie ? 0 : 1;
}

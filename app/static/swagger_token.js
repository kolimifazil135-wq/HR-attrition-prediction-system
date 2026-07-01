/**
 * Swagger UI — Automatic Token Interceptor
 *
 * HOW IT WORKS:
 *   1. You call any login endpoint (POST /auth/admin/login, POST /auth/user/login, etc.)
 *      via Swagger's "Try it out" panel.
 *   2. This script detects a successful login response and extracts the access_token.
 *   3. The token is stored in sessionStorage (browser memory — auto-cleared when the
 *      tab is closed; never written to disk or localStorage).
 *   4. Every subsequent Swagger API call automatically receives an
 *      "Authorization: Bearer <token>" header — no Authorize button needed.
 *   5. Calling POST /auth/logout clears the token from memory immediately.
 *
 * This file is served as a static asset and referenced by the /docs route.
 * No authentication logic lives in main.py.
 */

(function () {
    "use strict";

    const SESSION_KEY = "swagger_token";

    /** Endpoints whose JSON response may contain an access_token. */
    const TOKEN_SOURCE_SUFFIXES = ["/login", "/verify", "/verify-otp", "/google", "/callback"];

    /** Endpoints that should trigger a token wipe. */
    const LOGOUT_SUFFIXES = ["/logout"];

    const _originalFetch = window.fetch;

    window.fetch = async function (...args) {
        const url   = typeof args[0] === "string" ? args[0] : "";
        let options = args[1] || {};

        // ── Inject stored token into every non-schema request ──────────────
        if (url && !url.endsWith("openapi.json")) {
            const token = window.sessionStorage.getItem(SESSION_KEY);
            if (token) {
                options.headers = options.headers || {};
                if (options.headers instanceof Headers) {
                    options.headers.set("Authorization", "Bearer " + token);
                } else {
                    options.headers["Authorization"] = "Bearer " + token;
                }
            }
        }
        args[1] = options;

        const response = await _originalFetch.apply(this, args);

        // ── Capture token from successful login responses ───────────────────
        if (url && TOKEN_SOURCE_SUFFIXES.some(s => url.endsWith(s))) {
            response.clone().json().then(data => {
                if (data && data.access_token) {
                    window.sessionStorage.setItem(SESSION_KEY, data.access_token);
                    console.info(
                        "%c[HR Portal Swagger] ✓ Token captured — all requests will now be authenticated automatically.",
                        "color: #22c55e; font-weight: bold;"
                    );
                }
            }).catch(() => {/* non-JSON response — ignore */});
        }

        // ── Clear token on logout ───────────────────────────────────────────
        if (url && LOGOUT_SUFFIXES.some(s => url.endsWith(s))) {
            window.sessionStorage.removeItem(SESSION_KEY);
            console.info(
                "%c[HR Portal Swagger] Token cleared from session memory.",
                "color: #f59e0b; font-weight: bold;"
            );
        }

        return response;
    };

})();

"""Nagłówki bezpieczeństwa na własnym API - to samo, czego skaner wymaga od zbadanych hostów (web.SEC_HEADERS).

'unsafe-inline' w script-src/style-src wymusza stary UI (static/*.html: statyczne <script>/<style>, nie renderowane
z danych żądania) - nie odtwarza to naprawionego wcześniej XSS (onclick -> data-* + addEventListener), bo ten fix
usunął atrybut, a nie liczył na politykę CSP."""
from .. import auth

CSP = (
    "default-src 'self'; "
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
    "font-src 'self' https://fonts.gstatic.com; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def install(app):
    @app.middleware("http")
    async def security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Content-Security-Policy"] = CSP
        if auth.COOKIE_SECURE:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

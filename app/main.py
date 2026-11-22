"""ThreatLens - FastAPI uygulaması (Jinja2 sayfaları + JSON API). Çalıştırma: python run.py"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config
from .api import admin, attack, auth, cases, coverage, dashboard, entities, exports, graph, hunt, infrastructure, iocs, search
from .security import page_user

# Belgeler herkese açık değildir: /api/docs ve /api/openapi.json aşağıda oturum denetimiyle tanımlanır
app = FastAPI(title="ThreatLens API", version="1.0.0", docs_url=None, redoc_url=None, openapi_url=None,
              description="ThreatLens Tehdit İstihbaratı Platformu - MSSQL Graph + FastAPI (ORM yok, parametreli T-SQL)")

for module in (auth, dashboard, search, iocs, hunt, cases, graph, infrastructure, entities, attack, coverage, exports, admin):
    app.include_router(module.router)

app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
templates = Jinja2Templates(directory=config.TEMPLATES_DIR)
# Statik dosya sürümü: her başlatmada değişir, tarayıcı eski JS/CSS'i önbellekten kullanmaz
templates.env.globals["v"] = str(int(__import__("time").time()))

# Kenar çubuğu grupları: (grup başlığı, [(rota, sayfa anahtarı, başlık, Lucide ikon adı)])
NAV_GROUPS = [
    ("Analiz", [
        ("/", "overview", "Genel Bakış", "layout-dashboard"),
        ("/iocs", "iocs", "IOC Araştırma", "search"),
        ("/hunt", "hunt", "Log Avı", "radar"),
        ("/cases", "cases", "Vakalar", "briefcase"),
    ]),
    ("İstihbarat", [
        ("/graph", "graph", "İlişki Grafı", "share-2"),
        ("/infrastructure", "infrastructure", "Altyapı", "network"),
        ("/actors", "actors", "Tehdit Aktörleri", "users"),
        ("/campaigns", "campaigns", "Kampanyalar", "target"),
        ("/malware", "malware", "Zararlı Yazılımlar", "bug"),
        ("/attack", "attack", "MITRE ATT&CK", "grid-3x3"),
    ]),
    ("Yönetim", [
        ("/sources", "sources", "Veri Kaynakları", "database"),
        ("/audit", "audit", "Denetim Kayıtları", "file-clock"),
        ("/settings", "settings", "Ayarlar", "settings"),
    ]),
]
NAV = [item for _, items in NAV_GROUPS for item in items]
PAGES = {key: (title, path) for path, key, title, _ in NAV}


# -- hata biçimi: tüm API hataları {"detail": "..."} -----------------------
@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "istek"
    return JSONResponse({"detail": f"Geçersiz alan: {field} ({first.get('msg', 'hatalı değer')})", "errors": exc.errors()},
                        status_code=422)


def render(request: Request, page: str, template: str, **ctx):
    user = page_user(request)
    if user is None:
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)
    if "_db_error" in user:
        return templates.TemplateResponse(request, "error.html", {"message": user["_db_error"]}, status_code=503)
    title = PAGES.get(page, (ctx.get("title", "ThreatLens"), ""))[0]
    return templates.TemplateResponse(request, template, {"user": user, "nav": NAV, "nav_groups": NAV_GROUPS, "page": page,
                                                          "title": title, **ctx})


@app.get("/api/openapi.json", include_in_schema=False)
def openapi_schema(request: Request):
    if page_user(request) is None:
        return JSONResponse({"detail": "Oturum açmanız gerekiyor."}, status_code=401)
    return JSONResponse(app.openapi())


@app.get("/api/docs", include_in_schema=False)
def api_docs(request: Request):
    if page_user(request) is None:
        return RedirectResponse("/login?next=/api/docs", status_code=303)
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(openapi_url="/api/openapi.json", title="ThreatLens API")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request, next: str = "/"):
    # Oturumu açık kullanıcı giriş formunu yeniden görmez
    user = page_user(request)
    if user is not None and "_db_error" not in user:
        target = next if next.startswith("/") and not next.startswith("//") else "/"
        return RedirectResponse(target, status_code=303)
    return templates.TemplateResponse(request, "login.html", {"login_hint": config.LOGIN_HINT})


@app.get("/", include_in_schema=False)
def overview_page(request: Request):
    return render(request, "overview", "overview.html")


@app.get("/iocs", include_in_schema=False)
def iocs_page(request: Request):
    return render(request, "iocs", "iocs.html")


@app.get("/iocs/{indicator_id}", include_in_schema=False)
def ioc_detail_page(request: Request, indicator_id: int):
    return render(request, "iocs", "ioc_detail.html", indicator_id=indicator_id)


@app.get("/search", include_in_schema=False)
def search_page(request: Request):
    return render(request, "search", "search.html", title="Arama")


@app.get("/hunt", include_in_schema=False)
def hunt_page(request: Request):
    return render(request, "hunt", "hunt.html")


@app.get("/cases", include_in_schema=False)
def cases_page(request: Request):
    return render(request, "cases", "cases.html")


@app.get("/graph", include_in_schema=False)
def graph_page(request: Request):
    return render(request, "graph", "graph.html")


@app.get("/infrastructure", include_in_schema=False)
def infrastructure_page(request: Request):
    return render(request, "infrastructure", "infrastructure.html")


@app.get("/actors", include_in_schema=False)
def actors_page(request: Request):
    return render(request, "actors", "actors.html")


@app.get("/campaigns", include_in_schema=False)
def campaigns_page(request: Request):
    return render(request, "campaigns", "campaigns.html")


@app.get("/malware", include_in_schema=False)
def malware_page(request: Request):
    return render(request, "malware", "malware.html")


@app.get("/attack", include_in_schema=False)
def attack_page(request: Request):
    return render(request, "attack", "attack.html")


@app.get("/sources", include_in_schema=False)
def sources_page(request: Request):
    return render(request, "sources", "sources.html")


@app.get("/audit", include_in_schema=False)
def audit_page(request: Request):
    return render(request, "audit", "audit.html")


@app.get("/settings", include_in_schema=False)
def settings_page(request: Request):
    return render(request, "settings", "settings.html")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return RedirectResponse("/static/img/logo.svg")


@app.exception_handler(404)
async def not_found(request: Request, exc: HTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"detail": getattr(exc, "detail", "Bulunamadı.")}, status_code=404)
    return templates.TemplateResponse(request, "error.html", {"message": "Aradığınız sayfa bulunamadı.", "code": 404},
                                      status_code=404)

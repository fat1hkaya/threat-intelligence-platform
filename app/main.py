"""ThreatLens - FastAPI uygulaması (Jinja2 sayfaları + JSON API). Çalıştırma: python run.py"""
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import config
from .api import admin, attack, auth, dashboard, entities, graph, iocs
from .security import page_user

app = FastAPI(title="ThreatLens API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json",
              description="ThreatLens Tehdit İstihbaratı Platformu - MSSQL Graph + FastAPI (ORM yok, parametreli T-SQL)")

for module in (auth, dashboard, iocs, graph, entities, attack, admin):
    app.include_router(module.router)

app.mount("/static", StaticFiles(directory=config.STATIC_DIR), name="static")
templates = Jinja2Templates(directory=config.TEMPLATES_DIR)
# Statik dosya sürümü: her başlatmada değişir, tarayıcı eski JS/CSS'i önbellekten kullanmaz
templates.env.globals["v"] = str(int(__import__("time").time()))

# Kenar çubuğu: (rota, sayfa anahtarı, başlık, Lucide ikon adı)
NAV = [
    ("/", "overview", "Genel Bakış", "layout-dashboard"),
    ("/iocs", "iocs", "IOC Araştırma", "search"),
    ("/graph", "graph", "İlişki Grafı", "share-2"),
    ("/actors", "actors", "Tehdit Aktörleri", "users"),
    ("/campaigns", "campaigns", "Kampanyalar", "target"),
    ("/malware", "malware", "Zararlı Yazılımlar", "bug"),
    ("/attack", "attack", "MITRE ATT&CK", "grid-3x3"),
    ("/sources", "sources", "Veri Kaynakları", "database"),
    ("/audit", "audit", "Denetim Kayıtları", "file-clock"),
    ("/settings", "settings", "Ayarlar", "settings"),
]
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
    return templates.TemplateResponse(request, template, {"user": user, "nav": NAV, "page": page, "title": title, **ctx})


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@app.get("/", include_in_schema=False)
def overview_page(request: Request):
    return render(request, "overview", "overview.html")


@app.get("/iocs", include_in_schema=False)
def iocs_page(request: Request):
    return render(request, "iocs", "iocs.html")


@app.get("/iocs/{indicator_id}", include_in_schema=False)
def ioc_detail_page(request: Request, indicator_id: int):
    return render(request, "iocs", "ioc_detail.html", indicator_id=indicator_id)


@app.get("/graph", include_in_schema=False)
def graph_page(request: Request):
    return render(request, "graph", "graph.html")


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

from fastapi import APIRouter, HTTPException, Query
from typing import Optional, Dict, Any
import httpx
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import json
import os
import time

router = APIRouter()

CACHE_PATH = os.path.join("backend", "data", "site_preview_cache.json")
CACHE_TTL_SECONDS = 24 * 60 * 60

_def_cache: Dict[str, Dict[str, Any]] = {}


def _load_cache() -> None:
    global _def_cache
    try:
        if os.path.exists(CACHE_PATH):
            with open(CACHE_PATH, "r", encoding="utf-8") as f:
                _def_cache = json.load(f)
    except Exception:
        _def_cache = {}


def _save_cache() -> None:
    try:
        os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_def_cache, f)
    except Exception:
        pass


def _cache_get(url: str) -> Optional[Dict[str, Any]]:
    rec = _def_cache.get(url)
    if not rec:
        return None
    ts = rec.get("_ts", 0)
    if time.time() - ts > CACHE_TTL_SECONDS:
        return None
    return rec


def _cache_set(url: str, data: Dict[str, Any]) -> None:
    data = dict(data)
    data["_ts"] = time.time()
    _def_cache[url] = data


def _resolve(base: str, maybe: Optional[str]) -> Optional[str]:
    if not maybe:
        return None
    try:
        if bool(urlparse(maybe).netloc):
            return maybe
        return urljoin(base, maybe)
    except Exception:
        return None


async def _fetch_preview(url: str) -> Dict[str, Any]:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36 ProjectPenguinPreview/2.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    }
    async with httpx.AsyncClient(follow_redirects=True, timeout=12, headers=headers) as client:
        resp = await client.get(url)
        resp.raise_for_status()
        html = resp.text
    soup = BeautifulSoup(html, "html.parser")

    title = None
    # Prefer og:title when present
    og_title = soup.find("meta", attrs={"property": "og:title"})
    if og_title and og_title.get("content"):
        title = og_title["content"].strip()
    if not title and soup.title and soup.title.string:
        title = soup.title.string.strip()

    description = None
    og_desc = soup.find("meta", attrs={"property": "og:description"}) or soup.find("meta", attrs={"name": "description"})
    if og_desc and og_desc.get("content"):
        description = og_desc["content"].strip()

    og_image = soup.find("meta", attrs={"property": "og:image"})
    tw_image = soup.find("meta", attrs={"name": "twitter:image"})
    image = og_image.get("content") if og_image and og_image.get("content") else None
    if not image and tw_image and tw_image.get("content"):
        image = tw_image["content"]

    # Favicon (look for multiple rel variants)
    icon = (
        soup.find("link", rel=lambda v: v and "icon" in v.lower()) or
        soup.find("link", attrs={"rel": "shortcut icon"}) or
        soup.find("link", attrs={"rel": "icon"})
    )
    favicon = icon.get("href") if icon and icon.get("href") else "/favicon.ico"

    final_url = url
    image = _resolve(final_url, image)
    favicon = _resolve(final_url, favicon)
    # Fallback: if no Open Graph/Twitter image, use the favicon so UI shows something
    if not image and favicon:
        image = favicon

    return {
        "finalUrl": final_url,
        "title": title,
        "description": description,
        "image": image,
        "favicon": favicon,
    }


@router.get("")
@router.get("/")
async def get_site_preview(url: str = Query(..., description="Target URL to preview")):
    """Return a resilient preview payload.

    Never fails for normal inputs; on error returns a minimal payload
    using origin favicon and hostname as title so the UI always has
    something to render.
    """
    if not url.lower().startswith("http"):
        url = "http://" + url
    if not _def_cache:
        _load_cache()
    cached = _cache_get(url)
    if cached:
        return {k: v for k, v in cached.items() if k != "_ts"}
    try:
        data = await _fetch_preview(url)
        _cache_set(url, data)
        _save_cache()
        return data
    except Exception:
        # Fallback: construct minimal preview from the origin
        try:
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            fallback = {
                "finalUrl": url,
                "title": parsed.netloc or url,
                "description": None,
                "image": f"{origin}/favicon.ico",
                "favicon": f"{origin}/favicon.ico",
            }
            _cache_set(url, fallback)
            _save_cache()
            return fallback
        except Exception as e:
            # Last resort
            return {
                "finalUrl": url,
                "title": url,
                "description": None,
                "image": None,
                "favicon": None,
                "error": str(e)
            }



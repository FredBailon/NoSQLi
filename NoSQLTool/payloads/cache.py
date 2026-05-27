import os
import requests


def download_if_updated(url, cache_file, etag_file, timeout, force_revalidate=False):
    os.makedirs(os.path.dirname(cache_file), exist_ok=True)

    headers = {}
    if force_revalidate:
        # Fuerza revalidacion en caches intermedios/CDN cuando se necesite.
        headers["Cache-Control"] = "no-cache"
        headers["Pragma"] = "no-cache"

    if os.path.exists(etag_file):
        with open(etag_file, "r", encoding="utf-8") as f:
            etag = f.read().strip()
            if etag:
                headers["If-None-Match"] = etag

    response = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        allow_redirects=True
    )

    if response.status_code == 304:
        return False

    if response.status_code != 200:
        raise RuntimeError(f"Error HTTP {response.status_code} al descargar payloads desde {url}")

    with open(cache_file, "w", encoding="utf-8") as f:
        f.write(response.text)

    response_etag = response.headers.get("ETag")
    if response_etag:
        with open(etag_file, "w", encoding="utf-8") as f:
            f.write(response_etag)
    elif os.path.exists(etag_file):
        # Si el origen deja de enviar ETag, evita reutilizar uno obsoleto.
        os.remove(etag_file)

    return True

"""Build a Firefox package from the maintained Chrome source, without dependencies."""
from pathlib import Path
import argparse
import base64
import hashlib
import html
import json
import shutil
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ADDON_ID = "rf5-recon@rogerf5.dev"
FILES = ("popup.html", "popup.js", "popup.css", "service-worker.js", "icon128.png")
PRIVACY = (
    "RF5 Recon runs only when you press Ejecutar Recon on the active HTTP(S) tab.",
    "The selected hostname is sent to Google Public DNS (dns.google) to obtain A, AAAA, NS, MX and TXT records. Google receives the hostname and ordinary network request metadata, including the source IP address. Google's own privacy terms apply to that service.",
    "The extension requests the selected page and robots.txt, sitemap.xml and .well-known/security.txt from the inspected website. The website receives those ordinary HTTP requests.",
    "Page structure, links, forms and cookie security attributes are processed locally. Form field values and cookie values are not included in the report.",
    "Reports remain in the browser and are downloaded locally only when you choose to export JSON. RF5 Recon has no developer-operated report server, telemetry or advertising.",
    "Avoid sharing exported reports publicly without checking them: URLs, page metadata and discovered links may contain confidential information.",
)

def build(destination):
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    package = destination / "extension"
    package.mkdir(parents=True, exist_ok=True)
    for filename in FILES:
        shutil.copyfile(ROOT / filename, package / filename)

    manifest["background"] = {"scripts": ["service-worker.js"], "type": "module"}
    manifest["browser_specific_settings"] = {"gecko": {
        "id": ADDON_ID,
        "strict_min_version": "140.0",
        "data_collection_permissions": {"required": ["browsingActivity"]},
    }}
    manifest["description"] = "Reconocimiento web bajo demanda: DNS, headers, cookies, recursos observados y reporte JSON."
    (package / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    worker = (package / "service-worker.js").read_text(encoding="utf-8")
    if worker.count("chrome.") != 4:
        raise RuntimeError("Upstream API calls changed; review the Firefox adapter.")
    worker = "const extensionApi = globalThis.browser ?? globalThis.chrome;\n" + worker.replace("chrome.", "extensionApi.")
    old = "extensionApi.cookies.getAll({ url: tab.url })"
    new = "extensionApi.cookies.getAll({ url: tab.url, ...(tab.cookieStoreId ? { storeId: tab.cookieStoreId } : {}) })"
    if worker.count(old) != 1:
        raise RuntimeError("Cookie collection changed; review Firefox container handling.")
    (package / "service-worker.js").write_text(worker.replace(old, new), encoding="utf-8")

    css = (package / "popup.css").read_text(encoding="utf-8")
    css = css.replace(chr(96) + "nheader", "\nheader")
    css += "\n.privacy-notice{font-size:11px;color:var(--muted);margin-top:14px}.privacy-notice a{color:var(--light)}\n"
    (package / "popup.css").write_text(css, encoding="utf-8")

    popup = (package / "popup.html").read_text(encoding="utf-8")
    disclosure = '<p class="privacy-notice">Al ejecutar Recon, se consulta Google Public DNS con el dominio seleccionado. <a href="privacy.html" target="_blank" rel="noopener">Privacidad</a></p>'
    if popup.count("</main>") != 1:
        raise RuntimeError("Popup structure changed; review the DNS disclosure.")
    (package / "popup.html").write_text(popup.replace("</main>", disclosure + "</main>"), encoding="utf-8")

    policy = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>RF5 Recon privacy</title><body><h1>RF5 Recon privacy</h1><ul>'
    policy += "".join("<li>" + html.escape(paragraph) + "</li>" for paragraph in PRIVACY)
    policy += '</ul><p>Source and support: <a href="https://github.com/RogerF5-Security/RF5-RECON">RogerF5-Security/RF5-RECON</a></p></body></html>\n'
    (package / "privacy.html").write_text(policy, encoding="utf-8")
    shutil.copyfile(ROOT / "docs/firefox/LICENSE", package / "LICENSE")

    archive = destination / ("RF5-Recon-Firefox-" + manifest["version"] + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as output:
        for file in sorted(package.iterdir()):
            data = file.read_bytes()
            info = zipfile.ZipInfo(file.name, date_time=(2026, 11, 9, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            output.writestr(info, data)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    archive.with_suffix(".zip.sha256").write_text(digest + "  " + archive.name + "\n")
    return archive

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist/firefox")
    args = parser.parse_args()
    print(build(args.output_dir.resolve()))


# RF5 RECON

Extensión Chrome Manifest V3 para reconocimiento pasivo de la pestaña web activa, diseñada para iniciar la recolección de evidencia en auditorías autorizadas.

## Capacidades

- IP pública y registros DNS A, AAAA, NS, MX y TXT mediante DNS-over-HTTPS.
- Headers HTTP, CSP, HSTS, cookies Secure/HttpOnly/SameSite y políticas del navegador.
- Tecnologías y versiones que la aplicación exponga: CMS, frameworks, servidor y WAF/CDN.
- Formularios, endpoints observados, scripts, enlaces a archivos sensibles y recursos estándar: robots.txt, sitemap.xml y security.txt.
- Hallazgos priorizados como indicios para validación manual y exportación JSON.

## Uso local

1. Descargue o clone el repositorio.
2. Abra chrome://extensions, active Modo desarrollador y use Cargar descomprimida sobre esta carpeta.
3. Abra una página HTTP(S), pulse RF5 Recon y seleccione Ejecutar Recon.

Los resultados DNS pueden pertenecer a una CDN/WAF y no necesariamente al servidor de origen. La extensión no realiza fuerza bruta, fuzzing ni enumeración activa de rutas.

## Publicación

Para actualizar la extensión publicada, cree un ZIP con manifest.json en la raíz y súbalo desde la ficha RF5 Recon del Chrome Web Store Developer Dashboard.

## Firefox / Mozilla Add-ons

The Firefox package is built from the maintained root source, with a small adapter for Firefox Manifest V3 background scripts and native browser APIs. It preserves the existing add-on ID, includes Firefox container cookie-store handling, and declares the selected-hostname lookup to Google Public DNS.

Requires Python 3, Node.js for the adapter tests, and Firefox 140 or later for the packaged extension.

Build: python scripts/build_firefox.py

Test: node --test tests/firefox.test.cjs

Output: dist/firefox/RF5-Recon-Firefox-3.1.2.zip

[Privacy policy](docs/firefox/PRIVACY.md) · [AMO listing and reviewer notes](docs/firefox/AMO_LISTING.md)


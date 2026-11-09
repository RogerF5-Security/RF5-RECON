# Mozilla Add-ons listing

Name: RF5 Recon

Summary (English):
On-demand web reconnaissance: inspect HTTP headers, cookie security, DNS records and observed resources, then export a JSON report.

Summary (Spanish):
Reconocimiento web bajo demanda: analiza cabeceras HTTP, seguridad de cookies, DNS y recursos observados; exporta un informe JSON.

## Description (English)

RF5 Recon helps security auditors collect an initial picture of the active website.

Press Ejecutar Recon on an HTTP(S) tab to:
- Inspect HTTP security headers, CSP and cookie security attributes.
- Query public DNS records: A, AAAA, NS, MX and TXT.
- Identify technology indicators exposed by the website.
- Inventory observed endpoints, scripts, links and form structure.
- Check robots.txt, sitemap.xml and .well-known/security.txt.
- Review findings with supporting evidence and export a local JSON report.

Findings are indicators for manual validation. A missing header or technology match does not by itself confirm an exploitable vulnerability. The extension does not brute-force paths, submit forms or run exploit payloads.

DNS lookups send the selected hostname to Google Public DNS. Page analysis and reports remain local; no report is sent to the developer. Cookie values and form field values are excluded from reports.

Firefox 140 or later is required. Use on websites you own or are authorized to assess.

Source and support: https://github.com/RogerF5-Security/RF5-RECON

## Descripción (español)

RF5 Recon ayuda a recopilar una vista inicial del sitio web activo durante auditorías de seguridad.

Al pulsar Ejecutar Recon en una pestaña HTTP(S), permite:
- Revisar cabeceras de seguridad HTTP, CSP y atributos de seguridad de cookies.
- Consultar registros DNS públicos A, AAAA, NS, MX y TXT.
- Identificar indicios de tecnologías expuestas por el sitio.
- Inventariar endpoints observados, scripts, enlaces y estructura de formularios.
- Comprobar robots.txt, sitemap.xml y .well-known/security.txt.
- Consultar indicios con evidencia y descargar un informe JSON local.

Los resultados requieren validación manual. La extensión no realiza fuerza bruta de rutas, no envía formularios ni ejecuta payloads de explotación.

Las consultas DNS envían el dominio seleccionado a Google Public DNS. El análisis y los informes permanecen localmente; no se envían al desarrollador. Los informes excluyen valores de cookies y de campos de formularios.

Requiere Firefox 140 o posterior. Utiliza la extensión en sitios propios o con autorización para evaluarlos.

## Release notes: 3.1.2

Updated Firefox from the 2.x line to the maintained RF5 Recon 3.1.2 source: DNS lookups, HTTP headers and cookie-security analysis, technology indicators, observed-resource inventory and JSON export. Adapted the Manifest V3 background script for Firefox, preserved the existing add-on ID, handled Firefox cookie stores, and documented the Google Public DNS requests and local report processing.

## Reviewer notes

This package contains readable JavaScript and CSS. It is generated with the standard-library Python script scripts/build_firefox.py from the repository's root Chrome source. No minifier, bundler, remote code or third-party JavaScript library is used.

The adapter selects Firefox's promise-based browser API for background orchestration, uses a Manifest V3 event page instead of a Chrome service worker, preserves the existing AMO add-on ID, and adds Firefox's browsingActivity data declaration because the selected hostname is sent to Google Public DNS.

Only run checks against an authorized HTTP(S) test page. Open the popup, press Ejecutar Recon, inspect the report and use Descargar Reporte JSON. The package needs no login, API key or paid service.

Privacy policy:
https://github.com/RogerF5-Security/RF5-RECON/blob/main/docs/firefox/PRIVACY.md


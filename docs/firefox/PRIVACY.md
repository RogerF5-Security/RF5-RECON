# RF5 Recon: privacidad

Esta política corresponde al paquete Firefox generado desde RF5 Recon 3.1.2.

## Cuándo se ejecuta

El reconocimiento comienza únicamente al pulsar Ejecutar Recon sobre la pestaña HTTP(S) activa.

## Consultas externas

- DNS: se envía el nombre del dominio seleccionado a Google Public DNS (dns.google) para consultar registros A, AAAA, NS, MX y TXT. Google recibe ese nombre y los metadatos normales de la conexión, incluida la IP de origen. El servicio se rige por sus propias condiciones de privacidad.
- HTTP: se solicita la página seleccionada y los recursos robots.txt, sitemap.xml y .well-known/security.txt al sitio auditado. El sitio recibe esas solicitudes normales.

## Datos procesados localmente

La extensión analiza estructura de página, enlaces, formularios, cabeceras HTTP y atributos de seguridad de cookies. El informe no incluye valores de campos de formularios ni valores de cookies.

El desarrollador no recibe los informes, cookies ni contenido de las páginas. No se incluye telemetría, publicidad ni un servidor de reportes del desarrollador.

El informe permanece en el navegador y se descarga localmente cuando el usuario elige exportarlo en JSON. Las URL, metadatos de página y enlaces descubiertos pueden contener información confidencial: revise el informe antes de compartirlo.

Firefox muestra el permiso de datos de navegación porque la consulta DNS transmite el dominio seleccionado. La extensión requiere Firefox 140 o posterior.

Código y soporte: https://github.com/RogerF5-Security/RF5-RECON

# RF5 Recon: privacy

Recon runs only after the user presses Ejecutar Recon on the active HTTP(S) tab.

The selected hostname is sent to Google Public DNS (dns.google) for A, AAAA, NS, MX and TXT lookups. Google receives the hostname and ordinary connection metadata, including the source IP address. Google's own privacy terms apply to that service.

The extension requests the inspected page and robots.txt, sitemap.xml and .well-known/security.txt from the inspected website.

Page structure, HTTP headers, observed resources, forms and cookie security attributes are processed locally. Form field values and cookie values are excluded from the report. The developer does not receive reports or page content. No developer-operated analytics, telemetry, advertising or report server is included.

JSON reports are downloaded locally at the user's request. URLs and discovered links may contain confidential information; review reports before sharing them.

Firefox requires consent for browsing-activity data because DNS queries transmit the selected hostname. Firefox 140 or later is required.


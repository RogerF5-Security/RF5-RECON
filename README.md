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

/* RF5 Recon v3: orchestration only. Page inspection runs in the active tab. */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type !== 'rf5:scan') return;
  (async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id || !tab.url || !/^https?:/i.test(tab.url)) {
      throw new Error('Abra una pagina HTTP o HTTPS para iniciar el reconocimiento.');
    }
    const [{ result: page }] = await chrome.scripting.executeScript({
      target: { tabId: tab.id }, func: inspectPage
    });
    const [cookies, dns, discovery] = await Promise.all([
      chrome.cookies.getAll({ url: tab.url }), resolveDns(new URL(tab.url).hostname), getStandardFiles(new URL(tab.url).origin)
    ]);
    const normalizedCookies = cookies.map(normalizeCookie);
    const cookieFindings = evaluateCookies(normalizedCookies, tab.url);
    sendResponse({ ok: true, report: { ...page, dns, discovery, cookies: normalizedCookies, findings: [...page.findings, ...cookieFindings] } });
  })().catch(error => sendResponse({ ok: false, error: error.message }));
  return true;
});

function normalizeCookie(cookie) {
  return {
    name: cookie.name, domain: cookie.domain, path: cookie.path,
    secure: cookie.secure, httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite || 'unspecified', session: cookie.session,
    expirationDate: cookie.expirationDate || null
  };
}

async function resolveDns(hostname) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':')) return { hostname, note: 'El objetivo ya es una dirección IP.' };
  const lookup = async type => {
    try {
      const response = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=${type}`, { cache: 'no-store' });
      const json = await response.json();
      return (json.Answer || []).map(answer => answer.data).filter(Boolean);
    } catch { return []; }
  };
  const [ipv4, ipv6, nameservers, mx, txt] = await Promise.all([lookup('A'), lookup('AAAA'), lookup('NS'), lookup('MX'), lookup('TXT')]);
  return { hostname, ipv4, ipv6, nameservers, mx, txt, source: 'Google Public DNS (DoH)', note: 'Son registros DNS públicos; una CDN/WAF puede ocultar el servidor de origen.' };
}

async function getStandardFiles(origin) {
  const paths = ['/robots.txt', '/sitemap.xml', '/.well-known/security.txt'];
  const results = await Promise.all(paths.map(async path => {
    try { const response = await fetch(`${origin}${path}`, { cache: 'no-store', redirect: 'follow' }); return { path, status: response.status, available: response.ok, finalUrl: response.url }; }
    catch (error) { return { path, status: null, available: false, error: error.message }; }
  }));
  return results;
}

function evaluateCookies(cookies, url) {
  const findings = [];
  const isHttps = url.startsWith('https:');
  for (const cookie of cookies) {
    if (isHttps && !cookie.secure) findings.push({ severity: 'medium', title: `Cookie sin Secure: ${cookie.name}`, detail: 'Puede enviarse por HTTP si el dominio también lo acepta.', evidence: cookie.domain });
    if (!cookie.httpOnly) findings.push({ severity: 'low', title: `Cookie sin HttpOnly: ${cookie.name}`, detail: 'Es accesible desde JavaScript; revise el impacto ante XSS.', evidence: cookie.domain });
    if (cookie.sameSite === 'no_restriction' && !cookie.secure) findings.push({ severity: 'medium', title: `SameSite=None sin Secure: ${cookie.name}`, detail: 'Configuración inconsistente o expuesta a contexto cruzado.', evidence: cookie.domain });
  }
  return findings;
}

async function inspectPage() {
  const findings = [];
  const add = (severity, title, detail, evidence = '') => findings.push({ severity, title, detail, evidence });
  const unique = values => [...new Set(values.filter(Boolean))];
  const url = new URL(location.href);
  const headers = {};
  try {
    const response = await fetch(location.href, { cache: 'no-store', credentials: 'include' });
    response.headers.forEach((value, key) => { headers[key.toLowerCase()] = value; });
  } catch (error) { add('info', 'Cabeceras no disponibles', 'La pagina impidio la solicitud de verificacion.', error.message); }

  const requiredHeaders = {
    'content-security-policy': ['high', 'Reduce el impacto de XSS e inyecciones de contenido.'],
    'strict-transport-security': ['medium', 'Solo aplica a sitios HTTPS; fuerza futuras conexiones seguras.'],
    'x-content-type-options': ['low', 'Evita MIME sniffing mediante nosniff.'],
    'referrer-policy': ['low', 'Limita la exposicion de la URL de origen.'],
    'permissions-policy': ['low', 'Restringe APIs sensibles del navegador.']
  };
  if (url.protocol === 'https:') requiredHeaders['x-frame-options'] = ['medium', 'Reduce el riesgo de framing no autorizado.'];
  for (const [header, [severity, detail]] of Object.entries(requiredHeaders)) {
    if (!headers[header]) add(severity, `Header ausente: ${header}`, detail);
  }
  const csp = headers['content-security-policy'];
  if (csp) {
    const risky = [];
    if (/unsafe-inline/i.test(csp)) risky.push("'unsafe-inline'");
    if (/unsafe-eval/i.test(csp)) risky.push("'unsafe-eval'");
    if (/\*\s*(;|$)/.test(csp)) risky.push('*');
    if (risky.length) add('medium', 'CSP permisiva', 'La politica contiene fuentes que reducen la proteccion frente a XSS.', risky.join(', '));
    if (!/object-src\s+'none'/i.test(csp)) add('low', 'CSP sin object-src none', 'Considere bloquear plugins embebidos con object-src.', csp);
  }
  if (url.protocol !== 'https:') add('high', 'Pagina sin HTTPS', 'La sesion y los datos pueden viajar sin cifrado.', url.href);

  const technologies = [];
  const html = document.documentElement.outerHTML.slice(0, 2_000_000);
  const generator = document.querySelector('meta[name="generator" i]')?.content;
  if (generator) technologies.push(`Generator: ${generator}`);
  const checks = [
    ['WordPress', /wp-content|wp-includes|wordpress/i], ['React', /__NEXT_DATA__|data-reactroot|react(?:\.production)?\.min\.js/i],
    ['Next.js', /__NEXT_DATA__|_next\/static/i], ['Vue.js', /__vue__|\/vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js/i],
    ['Angular', /ng-version|angular(?:\.min)?\.js/i], ['jQuery', /jquery(?:[-.]\d[^/]*)?(?:\.min)?\.js/i],
    ['Bootstrap', /bootstrap(?:\.min)?\.(?:css|js)/i], ['Cloudflare', /cloudflare|cf-ray/i],
    ['Google Analytics', /googletagmanager\.com|google-analytics\.com/i], ['Drupal', /sites\/(?:default|all)\/files|drupalSettings/i],
    ['Joomla', /\/media\/system\/js|Joomla!/i], ['Laravel', /laravel_session|XSRF-TOKEN/i], ['ASP.NET', /__VIEWSTATE|__EVENTVALIDATION|asp\.net/i],
    ['Google reCAPTCHA', /recaptcha(?:\.net|\.google\.com)/i]
  ];
  checks.forEach(([name, rx]) => { if (rx.test(html)) technologies.push(name); });
  if (window.jQuery?.fn?.jquery) technologies.push(`jQuery ${window.jQuery.fn.jquery}`);
  if (window.React?.version) technologies.push(`React ${window.React.version}`);
  if (headers.server) technologies.push(`Server: ${headers.server}`);
  if (headers['x-powered-by']) technologies.push(`X-Powered-By: ${headers['x-powered-by']}`);
  if (headers['via']) technologies.push(`Via: ${headers.via}`);

  const resources = performance.getEntriesByType('resource').map(item => item.name);
  const links = [...document.querySelectorAll('a[href]')].map(a => a.href);
  const forms = [...document.forms].map(form => ({ action: form.action || location.href, method: (form.method || 'get').toUpperCase(), inputs: [...form.elements].filter(el => el.name).map(el => ({ name: el.name, type: el.type || el.tagName.toLowerCase() })) }));
  for (const form of forms) {
    const hasSensitiveField = form.inputs.some(input => /password|token|secret|card|cc-|cvv/i.test(`${input.name} ${input.type}`));
    if (url.protocol === 'https:' && /^http:/i.test(form.action)) add('high', 'Formulario HTTPS con destino HTTP', 'Puede exponer datos introducidos en el formulario.', form.action);
    if (hasSensitiveField && form.method === 'GET') add('medium', 'Campo sensible enviado por GET', 'Los datos pueden quedar expuestos en la URL e historiales.', form.action);
  }
  const endpoints = unique([...resources, ...links].filter(value => {
    try { return new URL(value).origin === location.origin; } catch { return false; }
  })).filter(value => /\/((api|graphql|admin|login|auth|v\d+|swagger|openapi)(\/|\?|$))/i.test(value)).slice(0, 200);
  const scripts = unique([...document.scripts].map(script => script.src).filter(Boolean)).slice(0, 200);
  const exposed = unique(links.filter(value => /\.(?:bak|backup|old|orig|sql|log|env|ini|conf|config)(?:$|[?#])/i.test(value))).slice(0, 100);
  exposed.forEach(value => add('medium', 'Posible archivo sensible enlazado', 'Revise si el recurso es accesible y contiene informacion no publica.', value));

  const sensitiveParams = [];
  url.searchParams.forEach((value, key) => { if (/(token|auth|api[_-]?key|secret|password|session)/i.test(key)) sensitiveParams.push(key); });
  if (sensitiveParams.length) add('medium', 'Parametro sensible en URL', 'Los parametros pueden terminar en historiales, logs o Referer.', sensitiveParams.join(', '));
  const inlineHandlers = [...document.querySelectorAll('*')].filter(el => [...el.attributes].some(attr => /^on/i.test(attr.name))).length;
  if (inlineHandlers) add('low', 'Manejadores JavaScript inline', 'Aumentan la complejidad de una CSP estricta.', `${inlineHandlers} elementos`);

  return {
    meta: { url: location.href, origin: location.origin, hostname: url.hostname, protocol: url.protocol, title: document.title, scannedAt: new Date().toISOString(), status: document.readyState },
    headers, technologies: unique(technologies).sort(), forms, endpoints, scripts, exposedFiles: exposed,
    page: { metaTags: Object.fromEntries([...document.querySelectorAll('meta[name]')].map(m => [m.name, m.content])), links: links.length, resources: resources.length, inlineHandlers },
    findings
  };
}


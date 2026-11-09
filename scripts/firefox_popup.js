const $ = selector => document.querySelector(selector);
const extensionApi = globalThis.browser ?? globalThis.chrome;
let report;
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}
function field(parent, label, value) {
  parent.append(element('b', `${label}: `), document.createTextNode(String(value)), element('br'));
}
function section(title) {
  const node = element('div', undefined, 'section');
  node.append(element('h2', title));
  return node;
}
function render(data) {
  report = data;
  const general = section('Información general');
  field(general, 'URL', data.meta.url);
  field(general, 'Dominio', data.meta.hostname);
  field(general, 'IP DNS (A)', data.dns?.ipv4?.join(', ') || 'Sin registro A público');
  field(general, 'Fuente', data.dns?.source || 'No disponible');
  general.append(element('small', data.dns?.note || ''));
  const grid = element('div', undefined, 'grid');
  for (const [key, label] of [['findings', 'hallazgos'], ['technologies', 'tecnologías'], ['cookies', 'cookies'], ['endpoints', 'endpoints']]) {
    const metric = element('div', undefined, 'metric');
    metric.append(element('b', data[key].length), document.createTextNode(label));
    grid.append(metric);
  }
  const technologies = section('Tecnologías detectadas');
  for (const item of data.technologies) technologies.append(element('span', item, 'tag'));
  if (!data.technologies.length) technologies.append(document.createTextNode('Sin tecnologías identificadas.'));
  $('#summary').replaceChildren(general, grid, technologies);
  const findings = [element('h2', 'Hallazgos')];
  const levels = { high: 'ALTO', medium: 'MEDIO', low: 'BAJO', info: 'INFO' };
  for (const finding of data.findings) {
    const level = Object.hasOwn(levels, finding.severity) ? finding.severity : 'info';
    const card = element('article', undefined, `card finding ${level}`);
    card.append(element('h3', `${levels[level]} · ${finding.title}`), element('p', finding.detail));
    if (finding.evidence) card.append(element('small', finding.evidence));
    findings.push(card);
  }
  if (!data.findings.length) findings.push(element('div', 'Sin hallazgos pasivos en esta revisión.', 'card'));
  $('#findings').replaceChildren(...findings);
  const inventory = section('Recon básico');
  for (const [key, label] of [['forms', 'Formularios'], ['endpoints', 'Endpoints'], ['scripts', 'Scripts']]) field(inventory, label, data[key].length);
  field(inventory, 'DNS NS', data.dns?.nameservers?.join(', ') || 'No expuestos');
  field(inventory, 'Recursos estándar', data.discovery?.filter(item => item.available).map(item => `${item.path} (${item.status})`).join(', ') || 'Ninguno disponible');
  $('#inventory').replaceChildren(inventory);
  $('#raw').textContent = JSON.stringify(data, null, 2);
  for (const selector of ['#summary', '#findings', '#inventory', '#details', '#download']) $(selector).hidden = false;
}
$('#scan').addEventListener('click', async () => {
  $('#scan').disabled = true;
  $('#status').textContent = 'Analizando pestaña activa.';
  try {
    const response = await extensionApi.runtime.sendMessage({ type: 'rf5:scan' });
    if (!response?.ok) throw new Error(response?.error || 'Sin respuesta');
    render(response.report);
    $('#status').textContent = `Completado: ${response.report.meta.scannedAt}`;
  } catch (error) {
    $('#status').textContent = `Error: ${error.message}`;
  } finally {
    $('#scan').disabled = false;
  }
});
$('#download').addEventListener('click', () => {
  if (!report) return;
  const anchor = document.createElement('a');
  const url = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' }));
  anchor.href = url;
  anchor.download = `RF5-Recon-${new URL(report.meta.url).hostname}-${Date.now()}.json`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

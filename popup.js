const $ = selector => document.querySelector(selector);
let report;
const escapeHtml = value => String(value).replace(/[&<>'"]/g, char => ({ '&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;' })[char]);
const severity = value => ({ high: 'ALTO', medium: 'MEDIO', low: 'BAJO', info: 'INFO' }[value] || value.toUpperCase());
function render(data) {
  report = data;
  $('#summary').hidden = false;
  const ip = data.dns?.ipv4?.join(', ') || 'Sin registro A público';
  $('#summary').innerHTML = `<div class="section"><h2>Información General</h2><b>URL:</b> ${escapeHtml(data.meta.url)}<br><b>Dominio:</b> ${escapeHtml(data.meta.hostname)}<br><b>IP DNS (A):</b> ${escapeHtml(ip)}<br><b>Fuente:</b> ${escapeHtml(data.dns?.source || 'No disponible')}<br><small>${escapeHtml(data.dns?.note || '')}</small></div><div class="grid"><div class="metric"><b>${data.findings.length}</b>hallazgos</div><div class="metric"><b>${data.technologies.length}</b>tecnologías</div><div class="metric"><b>${data.cookies.length}</b>cookies</div><div class="metric"><b>${data.endpoints.length}</b>endpoints</div></div><div class="section"><h2>Tecnologías Detectadas</h2>${data.technologies.map(item => `<span class="tag">${escapeHtml(item)}</span>`).join('') || 'Sin tecnologías identificadas.'}</div>`;
  $('#findings').hidden = false;
  $('#findings').innerHTML = `<h2>Hallazgos</h2>${data.findings.length ? data.findings.map(finding => `<article class="card finding ${escapeHtml(finding.severity)}"><h3>${severity(finding.severity)} · ${escapeHtml(finding.title)}</h3><p>${escapeHtml(finding.detail)}</p>${finding.evidence ? `<small>${escapeHtml(finding.evidence)}</small>` : ''}</article>`).join('') : '<div class="card">Sin hallazgos pasivos en esta revisión.</div>'}`;
  $('#inventory').hidden = false;
  const available = data.discovery?.filter(item => item.available).map(item => `${item.path} (${item.status})`).join(', ') || 'Ninguno disponible';
  $('#inventory').innerHTML = `<div class="section"><h2>Recon básico</h2><b>Formularios:</b> ${data.forms.length} · <b>Endpoints:</b> ${data.endpoints.length} · <b>Scripts:</b> ${data.scripts.length}<br><b>DNS NS:</b> ${escapeHtml(data.dns?.nameservers?.join(', ') || 'No expuestos')}<br><b>Recursos estándar:</b> ${escapeHtml(available)}</div>`;
  $('#details').hidden = false; $('#raw').textContent = JSON.stringify(data, null, 2); $('#download').hidden = false;
}
$('#scan').addEventListener('click', () => { $('#scan').disabled = true; $('#status').textContent = 'Analizando pestaña activa…'; chrome.runtime.sendMessage({ type: 'rf5:scan' }, response => { $('#scan').disabled = false; if (chrome.runtime.lastError || !response?.ok) { $('#status').textContent = `Error: ${response?.error || chrome.runtime.lastError?.message || 'sin respuesta'}`; return; } $('#status').textContent = `Completado: ${response.report.meta.scannedAt}`; render(response.report); }); });
$('#download').addEventListener('click', () => { const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })); a.download = `RF5-Recon-${new URL(report.meta.url).hostname}-${Date.now()}.json`; a.click(); URL.revokeObjectURL(a.href); });


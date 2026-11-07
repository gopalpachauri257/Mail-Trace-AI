const API = 'http://127.0.0.1:8000';
let selected = null;
let lastResult = null;

const $ = id => document.getElementById(id);

$('choose').onclick = () => $('file').click();

$('file').onchange = e => setFile(e.target.files[0]);

$('sample').onclick = async () => {
  try {
    const r = await fetch('../sample_emails/suspicious_phishing.eml');
    if (!r.ok) throw new Error('Sample file not found');
    const b = await r.blob();
    setFile(new File([b], 'suspicious_phishing.eml', {type:'message/rfc822'}));
  } catch (e) {
    alert('Open the frontend with VS Code Live Server and make sure the sample_emails folder exists.');
  }
};

const drop = $('drop');
['dragenter','dragover'].forEach(type => drop.addEventListener(type, e => {
  e.preventDefault();
  drop.classList.add('dragging');
}));
['dragleave','drop'].forEach(type => drop.addEventListener(type, e => {
  e.preventDefault();
  drop.classList.remove('dragging');
}));
drop.addEventListener('drop', e => setFile(e.dataTransfer.files[0]));

function setFile(file) {
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.eml')) {
    alert('Please select an .eml file.');
    return;
  }
  if (file.size > 10 * 1024 * 1024) {
    alert('File is larger than the 10 MB limit.');
    return;
  }
  selected = file;
  $('selected').classList.remove('hidden');
  $('selected').textContent = `Evidence selected: ${file.name} • ${(file.size / 1024).toFixed(1)} KB`;
}

$('analyze').onclick = async () => {
  if (!selected) return alert('Choose an .eml file first.');
  $('analyze').textContent = 'Analyzing…';
  $('analyze').disabled = true;

  try {
    const fd = new FormData();
    fd.append('file', selected);
    const r = await fetch(API + '/api/analyze', {method:'POST', body:fd});
    if (!r.ok) throw new Error(await r.text());
    lastResult = await r.json();
    render(lastResult);
    await Promise.all([loadGraph(), loadIntel(lastResult.indicators.public_ips || [])]);
  } catch (e) {
    alert('Analysis failed: ' + e.message);
  } finally {
    $('analyze').textContent = 'Analyze Email';
    $('analyze').disabled = false;
  }
};

$('report').onclick = async () => {
  if (!selected) return alert('Choose an .eml file first.');
  $('report').textContent = 'Creating PDF…';
  $('report').disabled = true;
  try {
    const fd = new FormData();
    fd.append('file', selected);
    const r = await fetch(API + '/api/report', {method:'POST', body:fd});
    if (!r.ok) throw new Error(await r.text());
    const blob = await r.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = selected.name.replace(/\.eml$/i,'') + '_forensic_report.pdf';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    alert('PDF report failed: ' + e.message);
  } finally {
    $('report').textContent = 'Download Forensic PDF';
    $('report').disabled = false;
  }
};

function render(x) {
  $('dashboard').classList.remove('hidden');

  $('score').textContent = x.risk.score;
  $('level').textContent = x.risk.level;
  $('level').className = x.risk.level.toLowerCase();

  $('spf').textContent = x.authentication.spf;
  $('dkim').textContent = x.authentication.dkim;
  $('dmarc').textContent = x.authentication.dmarc;
  $('urls').textContent = x.indicators.urls.length;
  $('ips').textContent = x.indicators.public_ips.length;

  $('caseId').textContent = 'MF-' + x.file.sha256.slice(0,8).toUpperCase();

  $('email').innerHTML = Object.entries({
    'From': x.email.from,
    'To': x.email.to,
    'Subject': x.email.subject,
    'Date': x.email.date,
    'Reply-To': x.email.reply_to || '—',
    'Return-Path': x.email.return_path || '—'
  }).map(([k,v]) =>
    `<div class="row"><label>${esc(k)}</label><div>${esc(v)}</div></div>`
  ).join('');

  $('classLevel').textContent = x.risk.level;
  $('classLevel').className = x.risk.level.toLowerCase();
  $('classText').textContent =
    x.risk.level === 'HIGH' ? 'Strong malicious / phishing indicators detected.' :
    x.risk.level === 'MEDIUM' ? 'Suspicious indicators require review.' :
    'No strong malicious indicators detected.';

  $('threatTag').textContent = x.risk.level;
  $('threatTag').className = 'tag ' + (x.risk.level === 'HIGH' ? 'red' : x.risk.level === 'MEDIUM' ? 'yellow' : 'green');

  $('reasons').innerHTML = x.risk.reasons.slice(0,12)
    .map(r => `<div class="reason">${esc(r)}</div>`).join('') ||
    '<div class="empty">No rule-based threat indicators.</div>';

  $('urlList').innerHTML = list(x.indicators.urls);
  $('ipList').innerHTML = list(x.indicators.public_ips);
  $('domainList').innerHTML = list(x.indicators.domains);

  $('authExplain').innerHTML = Object.entries(x.authentication).map(([k,v]) =>
    `<div class="authrow"><b>${esc(k.toUpperCase())}</b><strong class="${String(v).toLowerCase()}">${esc(v)}</strong></div>`
  ).join('');

  $('relay').innerHTML = x.relay_path.length
    ? x.relay_path.map((h,i) =>
      `<div class="hop"><small>HOP ${i+1}${h.public_ips.length ? ' • ' + esc(h.public_ips.join(', ')) : ''}</small><p>${esc(h.raw)}</p></div>`
    ).join('')
    : '<div class="empty">No Received headers found.</div>';

  $('hash').textContent = x.file.sha256;
  renderML(x);
}

function renderML(x) {
  const ml = x.ml || {};
  const classification = String(ml.classification || 'RULE-BASED').toUpperCase();
  const confidence = Number(ml.confidence);
  const reasons = Array.isArray(ml.reasons) ? ml.reasons : [];

  const human = reasons
    .map(r => String(r).toLowerCase())
    .map(r => {
      if (r.includes('verify') || r.includes('verification'))
        return 'Account verification language detected';
      if (r.includes('password') || r.includes('credential') || r.includes('login'))
        return 'Credential or login-related language detected';
      if (r.includes('urgent') || r.includes('immediately') || r.includes('suspend'))
        return 'Urgent or pressure-based language detected';
      if (r.includes('payment') || r.includes('invoice') || r.includes('bank') || r.includes('wire'))
        return 'Financial or payment-related language detected';
      if (r.includes('url') || r.includes('link'))
        return 'External link activity detected';
      return null;
    })
    .filter(Boolean);

  const uniqueReasons = [...new Set(human)].slice(0,5);
  if (!uniqueReasons.length && classification === 'PHISHING')
    uniqueReasons.push('The model detected language patterns associated with phishing.');

  const confText = Number.isFinite(confidence) ? `${confidence.toFixed(1)}%` : 'N/A';
  const modelText = ml.model || 'Rule-based forensic scoring';

  $('mlResult').innerHTML = `
    <div class="ml-box">
      <div class="cardhead">
        <h2>AI Threat Detection</h2>
        <span class="tag ${classification === 'PHISHING' ? 'red' : 'green'}">${esc(classification)}</span>
      </div>
      <div class="ml-grid">
        <div class="ml-stat">
          <small>CLASSIFICATION</small>
          <strong>${esc(classification)}</strong>
        </div>
        <div class="ml-stat">
          <small>CONFIDENCE</small>
          <strong>${confText}</strong>
        </div>
        <div class="ml-stat">
          <small>MODEL</small>
          <strong>${esc(modelText)}</strong>
        </div>
      </div>
      <div class="ml-explanation">
        <b>Why the model flagged this email</b>
        ${uniqueReasons.length
          ? uniqueReasons.map(r => `<span class="reason-tag">${esc(r)}</span>`).join('')
          : '<span class="muted">No additional model explanation was returned.</span>'}
      </div>
    </div>`;
}

function list(arr) {
  return arr && arr.length
    ? arr.slice(0,20).map(x => `<span class="ioc">${esc(x)}</span>`).join('')
    : '<span class="muted">None</span>';
}

async function loadIntel(ips) {
  $('intel').innerHTML = '';
  if (!ips.length) {
    $('intel').innerHTML = '<div class="empty">No public IPs available for infrastructure lookup.</div>';
    return;
  }

  for (const ip of ips.slice(0,5)) {
    const card = document.createElement('div');
    card.className = 'intelcard';
    card.innerHTML = `<h3>${esc(ip)}</h3><p>Querying infrastructure intelligence…</p>`;
    $('intel').appendChild(card);

    try {
      const r = await fetch(API + '/api/intel?ip=' + encodeURIComponent(ip), {method:'POST'});
      const j = await r.json();
      if (!r.ok) throw new Error(j.detail || 'Lookup failed');

      card.innerHTML = `
        <h3>${esc(ip)}</h3>
        <p><b>Location:</b> ${esc([j.city,j.region,j.country].filter(Boolean).join(', ') || 'Unavailable')}</p>
        <p><b>Org:</b> ${esc(j.org || 'Unavailable')}</p>
        <p><b>ASN:</b> ${esc(j.asn || 'Unavailable')}</p>
        <p><b>Source:</b> ${esc(j.source || j.status || 'n/a')}</p>`;
    } catch (e) {
      card.innerHTML = `<h3>${esc(ip)}</h3><p class="error">Intel unavailable</p>`;
    }
  }
}

async function loadGraph() {
  const fd = new FormData();
  fd.append('file', selected);
  try {
    const r = await fetch(API + '/api/graph', {method:'POST', body:fd});
    if (!r.ok) throw new Error();
    const g = await r.json();
    drawGraph(g);
  } catch (e) {
    $('graph').innerHTML = '<div class="empty">Graph unavailable.</div>';
  }
}

function drawGraph(g) {
  if (!g.nodes || !g.nodes.length) {
    $('graph').innerHTML = '<div class="empty">No relationships found.</div>';
    return;
  }

  const W = 900, H = 300, cx = W/2, cy = H/2;
  const pos = {};
  const radius = Math.min(320, 80 + g.nodes.length * 25);

  g.nodes.forEach((n,i) => {
    const a = (i / g.nodes.length) * Math.PI * 2;
    pos[n.id] = {
      x: cx + Math.cos(a) * radius,
      y: cy + Math.sin(a) * 95
    };
  });

  let svg = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Email correlation graph">`;

  (g.edges || []).forEach(e => {
    const a = pos[e.source], b = pos[e.target];
    if (a && b)
      svg += `<line class="edge" x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}"/>`;
  });

  g.nodes.forEach(n => {
    const p = pos[n.id];
    svg += `<g class="node">
      <circle cx="${p.x}" cy="${p.y}" r="27"/>
      <text x="${p.x}" y="${p.y+4}" text-anchor="middle">${esc(n.kind)}</text>
      <text x="${p.x}" y="${p.y+43}" text-anchor="middle">${esc(String(n.label).slice(0,28))}</text>
    </g>`;
  });

  svg += '</svg>';
  $('graph').innerHTML = svg;
}

function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  }[c]));
}

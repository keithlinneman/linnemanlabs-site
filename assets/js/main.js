// dropdowns
document.querySelectorAll('[data-dropdown-toggle]').forEach(btn => {
  btn.addEventListener('click', () => {
    btn.parentElement.classList.toggle('open');
  });
});
document.addEventListener('click', (e) => {
  document.querySelectorAll('[data-dropdown].open').forEach(d => {
    if (!d.contains(e.target)) d.classList.remove('open');
  });
});
document.addEventListener("keydown", e => {
    if (e.key === "Escape") {
        document.querySelectorAll("[data-dropdown].open").forEach(t => {
            t.classList.remove("open")
        })
    }
})

// content provenance - with a little help from claude
// Fetches app and content provenance from API and binds to data-bind attributes

const API = {
  content: '/api/provenance/content',
  contentSummary: '/api/provenance/content/summary',
  app: '/api/provenance/app/summary',
  appFull: '/api/provenance/app'
};

// formatters
const fmt = {
  bytes(b) {
    if (!b || b === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(b) / Math.log(k));
    return parseFloat((b / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  },
  date(iso) {
    return iso ? iso.split('T')[0] : '—';
  },
  datetime(iso) {
    return iso ? iso.replace('T', ' ').substring(0, 19) + 'Z' : '—';
  },
  hash(h, len = 24) {
    return h ? h.substring(0, len) + '...' : '—';
  }
};

// traverse nested path like "content.bundle.version"
function resolve(obj, path) {
  return path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
}

// fetch JSON
async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error(`Fetch ${url} failed:`, err);
    return null;
  }
}

// bind data to elements
function bindData(container, data) {
  if (!container || !data) return;

  // data-bind: set text content
  container.querySelectorAll('[data-bind]').forEach(el => {
    const key = el.dataset.bind;
    let value = resolve(data, key);
    if (value === null || value === undefined) return;

    const format = el.dataset.format;
    if (format === 'bytes') value = fmt.bytes(value);
    else if (format === 'date') value = fmt.date(value);
    else if (format === 'datetime') value = fmt.datetime(value);
    else if (format === 'hash') value = fmt.hash(value);

    el.textContent = value;
  });

  // data-bind-href: set href attribute
  container.querySelectorAll('[data-bind-href]').forEach(el => {
    const value = resolve(data, el.dataset.bindHref);
    if (value) el.href = value;
  });

  // data-bind-show: toggle visibility
  container.querySelectorAll('[data-bind-show]').forEach(el => {
    const value = resolve(data, el.dataset.bindShow);
    el.classList.toggle('hidden', !value);
  });

  // data-bind-class: conditional classes (key:trueClass:falseClass)
  container.querySelectorAll('[data-bind-class]').forEach(el => {
    const [key, trueClass, falseClass] = el.dataset.bindClass.split(':');
    const value = resolve(data, key);
    if (trueClass) el.classList.toggle(trueClass, !!value);
    if (falseClass) el.classList.toggle(falseClass, !value);
  });

  // data-bind-list: render arrays or object key:value pairs as badges
  container.querySelectorAll('[data-bind-list]').forEach(el => {
    const value = resolve(data, el.dataset.bindList);
    if (!value) return;

    if (Array.isArray(value)) {
      if (value.length === 0) {
        el.innerHTML = '<span class="text-xs text-[rgb(var(--muted))]">None</span>';
      } else {
        el.innerHTML = value.map(item => `
          <span class="text-xs px-2 py-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]">
            <span class="text-[rgb(var(--accent))]">${item}</span>
          </span>
        `).join('');
      }
    } else if (typeof value === 'object') {
      el.innerHTML = Object.entries(value).map(([type, count]) => `
        <span class="text-xs px-2 py-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]">
          <span class="text-[rgb(var(--accent))]">${type}</span>
          <span class="text-[rgb(var(--muted))] ml-1">${count}</span>
        </span>
      `).join('');
    }
  });
}

// render per-scanner vulnerability breakdown
function renderScannerBreakdown(container, byScanner) {
  if (!container || !byScanner) return;

  const severities = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];
  const sevColors = {
    critical: 'var(--bad)',
    high: 'var(--warn)',
    medium: 'var(--accent)',
    low: 'var(--muted)',
    negligible: 'var(--muted)',
    unknown: 'var(--muted)'
  };

  container.innerHTML = Object.entries(byScanner).map(([scanner, results]) => {
    let content;
    if ('findings' in results) {
      // govulncheck-style: { findings: N, vuln_ids: [] }
      const ids = results.vuln_ids && results.vuln_ids.length > 0
        ? results.vuln_ids.map(id => `<span class="text-[rgb(var(--accent))]">${id}</span>`).join(', ')
        : '';
      content = `
        <div class="flex items-center gap-3">
          <span class="text-sm">${results.findings} finding${results.findings !== 1 ? 's' : ''}</span>
          ${ids ? `<span class="text-xs">${ids}</span>` : ''}
        </div>
      `;
    } else {
      // severity-count style: { critical: 0, high: 0, ... }
      content = `
        <div class="flex gap-2">
          ${severities.map(s => {
            const count = results[s] || 0;
            return `
              <div class="text-center">
                <div class="w-7 h-7 rounded flex items-center justify-center text-xs font-medium"
                     style="background: rgba(${sevColors[s]}, 0.15); color: rgb(${sevColors[s]})">
                  ${count}
                </div>
                <div class="text-[9px] text-[rgb(var(--muted))] mt-0.5">${s.charAt(0).toUpperCase()}</div>
              </div>
            `;
          }).join('')}
        </div>
      `;
    }

    return `
      <div class="flex items-center justify-between p-2 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]">
        <span class="text-xs font-medium mono w-28">${scanner}</span>
        ${content}
      </div>
    `;
  }).join('');
}

// initialize content provenance section
async function initContent() {
  const container = document.getElementById('provenance-content');
  if (!container) return;

  const apiData = await fetchJSON(API.content);
  
  if (!apiData) {
    const dot = container.querySelector('[data-bind="content.status-dot"]');
    const text = container.querySelector('[data-bind="content.status-text"]');
    if (dot) dot.classList.add('status-dot--bad');
    if (text) text.textContent = 'Unavailable';
    return;
  }

  // namespace under 'content' and add computed fields
  const data = {
    content: {
      ...apiData,
      'status-text': 'Verified',
      source: apiData.bundle?.source,
      build: apiData.bundle?.build,
      summary: {
        ...apiData.bundle?.summary,
        type_count: apiData.bundle?.summary?.file_types 
          ? Object.keys(apiData.bundle.summary.file_types).length 
          : 0
      },
      tooling: apiData.bundle?.tooling,
      'raw-json': JSON.stringify(apiData, null, 2)
    }
  };

  bindData(container, data);
}

// initialize app provenance section
async function initApp() {
  const container = document.getElementById('provenance-app');
  if (!container) return;

  const apiData = await fetchJSON(API.app);
  
  if (!apiData) {
    const dot = container.querySelector('[data-bind="app.status-dot"]');
    const text = container.querySelector('[data-bind="app.status-text"]');
    if (dot) dot.classList.add('status-dot--bad');
    if (text) text.textContent = 'Unavailable';
    return;
  }

  // flatten components[0] into binary + container
  const comp = apiData.components?.[0] || {};
  const data = {
    app: {
      ...apiData,
      'status-text': apiData.vulnerabilities?.gate_result === 'pass' ? 'Verified' : 'Warning',
      binary: comp.binary || {},
      container: {
        ...comp.oci,
        os: comp.os,
        arch: comp.arch,
        platform: comp.os && comp.arch ? `${comp.os}/${comp.arch}` : '—'
      },
      computed: {
        license_status: apiData.licenses?.compliant ? 'Compliant' : 'Non-Compliant',
        allow_vex_text: apiData.policy?.vulnerability?.allow_if_vex ? 'Yes' : 'No',
        allow_unknown_text: apiData.policy?.license?.allow_unknown ? 'Allowed' : 'Denied'
      },
      'raw-json': JSON.stringify(apiData, null, 2)
    }
  };

  bindData(container, data);

  // render per-scanner breakdown
  const scannerEl = document.getElementById('vuln-scanner-breakdown');
  if (scannerEl && apiData.vulnerabilities?.by_scanner) {
    renderScannerBreakdown(scannerEl, apiData.vulnerabilities.by_scanner);
  }

  // handle denied_found display
  const deniedEl = document.getElementById('denied-found-list');
  if (deniedEl && apiData.licenses?.denied_found?.length > 0) {
    deniedEl.innerHTML = apiData.licenses.denied_found.map(lic => `
      <span class="text-xs px-2 py-1 rounded border border-[rgb(var(--bad))]/50 bg-[rgb(var(--bad))]/10 text-[rgb(var(--bad))]">${lic}</span>
    `).join('');
  }
}

// initialize footer (uses summary endpoint)
async function initFooter() {
  const container = document.getElementById('content-provenance-footer');
  if (!container) return;

  const data = await fetchJSON(API.contentSummary);

  if (!data) {
    container.innerHTML = `
      <div class="flex items-center gap-2">
        <span class="status-dot status-dot--warn"></span>
        <span class="text-xs text-[rgb(var(--muted))]">Content provenance unavailable</span>
      </div>
    `;
    return;
  }

  container.innerHTML = `
    <div class="text-[rgb(var(--fg))] font-medium mb-1">Content Provenance</div>
    <div class="text-xs text-[rgb(var(--muted))] mb-3">
      Content bundle verified from ${data.source || 'unknown'} source.
    </div>
    <div class="grid gap-2">
      <div>
        <div class="attestation-label">Content Version</div>
        <div class="attestation-value tabular">${data.version || '—'}</div>
      </div>
      <div>
        <div class="attestation-label">Bundle SHA256</div>
        <div class="attestation-value text-xs">${data.content_hash || '—'}</div>
      </div>
      <div class="flex gap-6">
        <div>
          <div class="attestation-label">Generated</div>
          <div class="attestation-value tabular">${fmt.date(data.created_at)}</div>
        </div>
        <div>
          <div class="attestation-label">Files</div>
          <div class="attestation-value tabular">${data.total_files || '—'}</div>
        </div>
        <div>
          <div class="attestation-label">Size</div>
          <div class="attestation-value tabular">${fmt.bytes(data.total_size)}</div>
        </div>
      </div>
    </div>
    <div class="mt-3 pt-3 border-t border-[rgb(var(--border))]">
      <a href="/about/provenance/" class="text-xs text-[rgb(var(--accent))] hover:underline">
        View full provenance details →
      </a>
    </div>
  `;
}

// init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initFooter();
  initContent();
  initApp();
});
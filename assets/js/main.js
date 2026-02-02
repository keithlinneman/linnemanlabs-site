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
  app: '/api/provenance/app'
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

// resolve nested path like "content.bundle.version"
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

  // data-bind-list: render list items
  container.querySelectorAll('[data-bind-list]').forEach(el => {
    const value = resolve(data, el.dataset.bindList);
    if (value && typeof value === 'object') {
      el.innerHTML = Object.entries(value).map(([type, count]) => `
        <span class="text-xs px-2 py-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]">
          <span class="text-[rgb(var(--accent))]">${type}</span>
          <span class="text-[rgb(var(--muted))] ml-1">${count}</span>
        </span>
      `).join('');
    }
  });
}

// transform raw API response into flat bindable object for content
function flattenContent(data) {
  if (!data) return null;
  const b = data.bundle || {};
  const r = data.runtime || {};
  const s = b.source || {};
  const sum = b.summary || {};
  const t = b.tooling || {};

  return {
    'content.status-text': 'Verified',
    'content.bundle.version': b.version,
    'content.bundle.content_id': b.content_id,
    'content.bundle.content_hash': b.content_hash,
    'content.bundle.schema': b.schema,
    'content.bundle.type': b.type,
    'content.bundle.created_at': b.created_at,
    'content.source.repository': s.repository,
    'content.source.commit': s.commit,
    'content.source.branch': s.branch,
    'content.source.dirty': s.dirty,
    'content.source.commit_date': s.commit_date,
    'content.build.host': b.build?.host,
    'content.build.user': b.build?.user,
    'content.summary.total_files': sum.total_files,
    'content.summary.total_size': sum.total_size,
    'content.summary.type_count': sum.file_types ? Object.keys(sum.file_types).length : 0,
    'content.summary.file_types': sum.file_types,
    'content.tooling.hugo.version': t.hugo?.version,
    'content.tooling.hugo.sha256': t.hugo?.sha256,
    'content.tooling.tailwindcss.version': t.tailwindcss?.version,
    'content.tooling.tailwindcss.sha256': t.tailwindcss?.sha256,
    'content.tooling.tidy.version': t.tidy?.version,
    'content.tooling.tidy.sha256': t.tidy?.sha256,
    'content.tooling.git.version': t.git?.version,
    'content.tooling.bash.version': t.bash?.version,
    'content.runtime.source': r.source,
    'content.runtime.loaded_at': r.loaded_at,
    'content.runtime.server_time': r.server_time,
    'content.runtime.hash': r.hash,
    'content.raw-json': JSON.stringify(data, null, 2)
  };
}

// transform raw API response into flat bindable object for app
function flattenApp(data) {
  if (!data) return null;
  const s = data.source || {};
  const att = data.attestations || {};
  const pol = data.policy?.defaults || {};
  const vulns = data.vulnerabilities?.summary || {};
  const container = data.components?.[0]?.index || {};

  return {
    'app.status-text': 'Verified',
    'app.version': data.version,
    'app.build_id': data.build_id,
    'app.track': data.track,
    'app.created_at': data.created_at,
    'app.source.repository': s.repository,
    'app.source.commit': s.commit,
    'app.source.commit_short': s.commit_short,
    'app.source.branch': s.branch,
    'app.source.dirty': s.dirty,
    'app.source.commit_date': s.commit_date,
    'app.attestations.cosign.signed': att.cosign?.signed,
    'app.attestations.cosign.method': att.cosign?.method,
    'app.attestations.slsa.verified': att.slsa?.verified,
    'app.attestations.slsa.level': att.slsa?.level,
    'app.policy.signing': pol.signing?.require_signature,
    'app.policy.sbom': pol.evidence?.sbom?.required,
    'app.policy.scan': pol.evidence?.scan?.required,
    'app.policy.vuln_gating': pol.vulnerability?.gating?.block_on,
    'app.vulns.critical': vulns.critical,
    'app.vulns.high': vulns.high,
    'app.vulns.medium': vulns.medium,
    'app.vulns.low': vulns.low,
    'app.sbom.format': data.sbom?.format,
    'app.sbom.package_count': data.sbom?.package_count,
    'app.licenses.compliant': data.licenses?.compliant ? 'Yes' : 'No',
    'app.container.image': container.registry && container.repository ? `${container.registry}/${container.repository}` : null,
    'app.container.digest': container.digest,
    'app.container.tag': container.tag,
    'app.container.pushed_at': container.pushed_at,
    'app.raw-json': JSON.stringify(data, null, 2)
  };
}

// initialize content provenance section
async function initContent() {
  const container = document.getElementById('provenance-content');
  if (!container) return;

  const data = await fetchJSON(API.content);
  
  if (!data) {
    const dot = container.querySelector('[data-bind="content.status-dot"]');
    const text = container.querySelector('[data-bind="content.status-text"]');
    if (dot) dot.classList.add('status-dot--bad');
    if (text) text.textContent = 'Unavailable';
    return;
  }

  bindData(container, flattenContent(data));
}

// initialize app provenance section
async function initApp() {
  const container = document.getElementById('provenance-app');
  if (!container) return;

  const data = await fetchJSON(API.app);
  
  if (!data) {
    const dot = container.querySelector('[data-bind="app.status-dot"]');
    const text = container.querySelector('[data-bind="app.status-text"]');
    if (dot) dot.classList.add('status-dot--bad');
    if (text) text.textContent = 'Unavailable';
    return;
  }

  bindData(container, flattenApp(data));
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

// initialize on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initFooter();
  initContent();
  initApp();
});
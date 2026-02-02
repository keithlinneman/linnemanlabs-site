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
// Fetches provenance from API and binds to data-bind attributes

const ProvenanceAPI = {
  summary: '/api/provenance/content/summary',
  full: '/api/provenance/content'
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

// resolve nested path like "bundle.source.commit"
function resolve(obj, path) {
  return path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
}

// Fetch JSON from endpoint
async function fetchJSON(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch (err) {
    console.error('Provenance fetch failed:', err);
    return null;
  }
}

// bind data to elements with data-bind attribute
function bindData(container, data, prefix = '') {
  if (!data) return;

  // find all elements with data-bind
  container.querySelectorAll('[data-bind]').forEach(el => {
    const key = el.dataset.bind;
    let value = resolve(data, key);

    if (value === null || value === undefined) return;

    // Apply formatters
    const format = el.dataset.format;
    if (format === 'bytes') value = fmt.bytes(value);
    else if (format === 'date') value = fmt.date(value);
    else if (format === 'datetime') value = fmt.datetime(value);
    else if (format === 'hash') value = fmt.hash(value);

    el.textContent = value;
  });

  // handle data-bind-href (for links)
  container.querySelectorAll('[data-bind-href]').forEach(el => {
    const key = el.dataset.bindHref;
    const value = resolve(data, key);
    if (value) el.href = value;
  });

  // handle data-bind-show (conditional visibility)
  container.querySelectorAll('[data-bind-show]').forEach(el => {
    const key = el.dataset.bindShow;
    const value = resolve(data, key);
    if (value) el.classList.remove('hidden');
    else el.classList.add('hidden');
  });

  // handle data-bind-list for file types
  container.querySelectorAll('[data-bind-list]').forEach(el => {
    const key = el.dataset.bindList;
    const value = resolve(data, key);
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

// footer provenance card
async function initFooter() {
  const container = document.getElementById('content-provenance-footer');
  if (!container) return;

  const data = await fetchJSON(ProvenanceAPI.summary);

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

// full provenance page
async function initPage() {
  const container = document.getElementById('provenance-full');
  if (!container) return;

  const data = await fetchJSON(ProvenanceAPI.full);

  if (!data) {
    // update status to show error
    const statusDot = container.querySelector('[data-bind="status-dot"]');
    const statusText = container.querySelector('[data-bind="status-text"]');
    if (statusDot) statusDot.classList.add('status-dot--bad');
    if (statusText) statusText.textContent = 'Unavailable';
    return;
  }

  // flatten data for easier binding
  const flat = {
    'status-text': 'Verified',
    'bundle.version': data.bundle?.version,
    'bundle.content_id': data.bundle?.content_id,
    'bundle.content_hash': data.bundle?.content_hash,
    'bundle.schema': data.bundle?.schema,
    'bundle.type': data.bundle?.type,
    'bundle.created_at': data.bundle?.created_at,
    'source.repository': data.bundle?.source?.repository,
    'source.commit': data.bundle?.source?.commit,
    'source.branch': data.bundle?.source?.branch,
    'source.dirty': data.bundle?.source?.dirty,
    'source.commit_date': data.bundle?.source?.commit_date,
    'build.host': data.bundle?.build?.host,
    'build.user': data.bundle?.build?.user,
    'summary.total_files': data.bundle?.summary?.total_files,
    'summary.total_size': data.bundle?.summary?.total_size,
    'summary.type_count': data.bundle?.summary?.file_types ? Object.keys(data.bundle.summary.file_types).length : 0,
    'summary.file_types': data.bundle?.summary?.file_types,
    'tooling.hugo.version': data.bundle?.tooling?.hugo?.version,
    'tooling.hugo.sha256': data.bundle?.tooling?.hugo?.sha256,
    'tooling.tailwindcss.version': data.bundle?.tooling?.tailwindcss?.version,
    'tooling.tailwindcss.sha256': data.bundle?.tooling?.tailwindcss?.sha256,
    'tooling.tidy.version': data.bundle?.tooling?.tidy?.version,
    'tooling.tidy.sha256': data.bundle?.tooling?.tidy?.sha256,
    'tooling.git.version': data.bundle?.tooling?.git?.version,
    'tooling.bash.version': data.bundle?.tooling?.bash?.version,
    'runtime.source': data.runtime?.source,
    'runtime.loaded_at': data.runtime?.loaded_at,
    'runtime.server_time': data.runtime?.server_time,
    'runtime.hash': data.runtime?.hash,
    'raw-json': JSON.stringify(data, null, 2)
  };

  bindData(container, flat);
}

// init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initFooter();
  initPage();
});
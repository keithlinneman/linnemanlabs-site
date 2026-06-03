// provenance.js - rendering for the /about/provenance/* pages only.
// Loaded via the `scripts` block in layouts/provenance/{combined,app,content}.html, NOT site-wide.
// Wrapped in an IIFE so its top-level names don't collide with main.js (both load on these pages).
(function () {

const API = {
  content: '/api/provenance/content',
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

// traverse nested path like "content.bundle.version"
function resolve(obj, path) {
  return path.split('.').reduce((o, k) => (o && o[k] !== undefined) ? o[k] : null, obj);
}

// fetch JSON (memoized per page load) - dev fallback when the inline data island is empty
// (e.g. under `hugo server`, where nothing injects it).
const _cache = new Map();

async function fetchJSON(url) {
  if (_cache.has(url)) return _cache.get(url);
  const promise = fetch(url)
    .then(res => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .catch(err => {
      console.error(`Fetch ${url} failed:`, err);
      _cache.delete(url);
      return null;
    });
  _cache.set(url, promise);
  return promise;
}

// read a <script type="application/json" id="..."> data island (inlined server-side, once, when the
// content bundle loads). returns the parsed object, or null if absent/empty/invalid so the caller can
// fall back to fetch (e.g. under `hugo server`, where nothing injects the island).
function readInlineJSON(id) {
  const el = document.getElementById(id);
  if (!el) return null;
  const txt = el.textContent.trim();
  if (!txt) return null;
  try { return JSON.parse(txt); } catch (e) { console.error(`Inline JSON #${id} parse failed:`, e); return null; }
}

// DOM helpers
// All dynamic content is built with DOM APIs instead of innerHTML so the
// page can run under a strict TrustedTypes CSP with no policy exceptions.

// h(tag, props, ...children) - create an element
//   props.class  -> className
//   props.text   -> textContent (use instead of children for text-only nodes)
//   all other props -> setAttribute
//   children: strings become text nodes, null/false are skipped
function h(tag, props, ...children) {
  const el = document.createElement(tag);
  if (props) {
    for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v);
    }
  }
  for (const c of children) {
    if (c != null && c !== false) el.append(c);
  }
  return el;
}

// SVG chevron (needs createElementNS) - used in expandable license groups
function chevronSvg(cls) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('class', cls);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('stroke', 'currentColor');
  const p = document.createElementNS(ns, 'path');
  p.setAttribute('stroke-linecap', 'round');
  p.setAttribute('stroke-linejoin', 'round');
  p.setAttribute('stroke-width', '2');
  p.setAttribute('d', 'M19 9l-7 7-7-7');
  svg.append(p);
  return svg;
}

// Data binding

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

  // data-bind-title: set title attribute (for tooltips)
  container.querySelectorAll('[data-bind-title]').forEach(el => {
    const value = resolve(data, el.dataset.bindTitle);
    if (value) el.title = value;
  });

  // data-bind-show: toggle visibility based on resolved value
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

  // data-bind-list: render arrays / object key:count pairs as .prov-chip chips.
  const CHIP_MOD   = { good: 'prov-chip--good', bad: 'prov-chip--bad', warn: 'prov-chip--warn', accent: '' };
  const CHIP_GLYPH = { good: '✓', bad: '✗', warn: '·' };  // checks/cross/dot: non-color status cue
  container.querySelectorAll('[data-bind-list]').forEach(el => {
    const value = resolve(data, el.dataset.bindList);
    if (!value) return;

    const fixedColor = el.dataset.bindListColor;
    const allow = el.dataset.bindListAllow ? (resolve(data, el.dataset.bindListAllow) || []) : null;
    const deny  = el.dataset.bindListDeny  ? (resolve(data, el.dataset.bindListDeny)  || []) : null;
    const stateFor = name => {
      if (fixedColor)                    return fixedColor;          // 'good' | 'bad' | 'warn' | 'accent'
      if (deny  && deny.includes(name))  return 'bad';
      if (allow && allow.includes(name)) return 'good';
      if (allow || deny)                 return 'warn';
      return 'accent';
    };
    const chip = (name, count) => {
      const state = stateFor(name);
      const kids = [];
      if (CHIP_GLYPH[state]) kids.push(h('span', { class: 'prov-chip__glyph prov-glyph--' + state, text: CHIP_GLYPH[state] }));
      kids.push(h('span', { class: 'prov-chip__name', text: name }));
      if (count != null) kids.push(h('span', { class: 'prov-chip__count', text: String(count) }));
      return h('span', { class: ('prov-chip ' + (CHIP_MOD[state] || '')).trim() }, ...kids);
    };

    el.replaceChildren();

    if (Array.isArray(value)) {
      if (value.length === 0) {
        el.append(h('span', { class: 'prov-empty', text: 'None' }));
      } else {
        value.forEach(item => el.append(chip(String(item))));
      }
    } else if (typeof value === 'object') {
      for (const [type, count] of Object.entries(value)) {
        el.append(chip(type, count));
      }
    }
  });
}

// Vulnerability rendering - severity badges, scanner breakdown, findings list

// severity -> short key for .prov-sevgrid__num--<key> and .prov-badge--<key>
const SEV_KEY = {
  critical: 'crit', high: 'high', medium: 'med',
  low: 'low', negligible: 'negl', unknown: 'unknown'
};
const sevKey = s => SEV_KEY[s] || 'unknown';

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];

// render per-scanner vulnerability breakdown
function renderScannerBreakdown(container, byScanner) {
  if (!container || !byScanner) return;
  container.replaceChildren();

  for (const [scanner, results] of Object.entries(byScanner)) {
    const row = h('div', { class: 'prov-itemrow' },
      h('span', { class: 'prov-itemrow__name', text: scanner })
    );

    if ('findings' in results) {
      const content = h('div', { class: 'prov-itemrow__meta' },
        h('span', { text: results.findings + ' finding' + (results.findings !== 1 ? 's' : '') })
      );

      if (results.vuln_ids && results.vuln_ids.length > 0) {
        const ids = h('span', { class: 'prov-accent' });
        results.vuln_ids.forEach((id, i) => {
          if (i > 0) ids.append(', ');
          ids.append(h('span', { text: id }));
        });
        content.append(ids);
      }
      row.append(content);
    } else {
      const grid = h('div', { class: 'prov-sevgrid prov-sevgrid--mini' });
      for (const s of SEV_ORDER) {
        grid.append(
          h('div', null,
            h('div', { class: 'prov-sevgrid__num prov-sevgrid__num--' + sevKey(s), text: String(results[s] || 0) }),
            h('div', { class: 'prov-sevgrid__label', text: s.charAt(0).toUpperCase() })
          )
        );
      }
      row.append(grid);
    }

    container.append(row);
  }
}

// render vulnerability findings list
function renderFindings(container, findings) {
  if (!container) return;

  if (!findings || findings.length === 0) {
    container.replaceChildren(
      h('span', { class: 'prov-empty prov-empty--good', text: 'No findings' })
    );
    return;
  }

  container.replaceChildren();

  for (const f of findings) {
    const key = sevKey(f.severity);

    // header row: severity badge + id (left), scanner chips (right)
    const lead = h('div', { class: 'prov-finding__lead' },
      h('span', { class: 'prov-badge prov-badge--' + key, text: f.severity })
    );

    if (f.source_url) {
      lead.append(h('a', {
        class: 'prov-finding__id', href: f.source_url, target: '_blank', rel: 'noopener', text: f.id
      }));
    } else {
      lead.append(h('span', { class: 'prov-finding__id', text: f.id }));
    }

    const scanners = h('div', { class: 'prov-finding__scanners' });
    for (const s of f.scanners) {
      scanners.append(h('span', { class: 'prov-chip prov-chip--muted' },
        h('span', { class: 'prov-chip__name', text: s })
      ));
    }

    const card = h('div', { class: 'prov-finding' },
      h('div', { class: 'prov-finding__head' }, lead, scanners)
    );

    // optional title (CSS clamps to 2 lines)
    if (f.title) {
      card.append(h('div', { class: 'prov-finding__title', text: f.title }));
    }

    // metadata: package, installed, fixed
    const meta = h('div', { class: 'prov-finding__meta' },
      h('div', null,
        h('span', { class: 'prov-muted', text: 'Package: ' }),
        h('span', { class: 'mono', text: f.package || '—' })
      ),
      h('div', null,
        h('span', { class: 'prov-muted', text: 'Installed: ' }),
        h('span', { class: 'mono', text: f.installed_version || '—' })
      )
    );

    if (f.fixed_version) {
      meta.append(
        h('div', null,
          h('span', { class: 'prov-muted', text: 'Fixed: ' }),
          h('span', { class: 'mono prov-good', text: f.fixed_version })
        )
      );
    }

    card.append(meta);
    container.append(card);
  }
}

// SBOM package list

function renderPackageList(container, packages) {
  if (!container) return;

  if (!packages || packages.length === 0) {
    container.replaceChildren(
      h('span', { class: 'prov-empty', text: 'No packages' })
    );
    return;
  }

  const list = h('div', { class: 'prov-list' });

  for (const pkg of packages) {
    list.append(
      h('div', { class: 'prov-itemrow' },
        h('div', { class: 'prov-itemrow__name', text: pkg.name }),
        h('div', { class: 'prov-itemrow__meta' },
          h('span', { text: pkg.version }),
          h('span', { class: 'prov-itemrow__lic ' + statusTextClass(pkg.license_status), text: pkg.license || 'none' })
        )
      )
    );
  }

  container.replaceChildren(list);
}

// Dense file table for the evidence ledgers (attestation / evidence /
// content-bundle file inventories). Display-only: builds a .prov-table from
// already-fetched arrays. columns: [{ key, label, format? ('bytes'|'hash') }]
function renderFileTable(container, files, columns) {
  if (!container) return;

  if (!files || files.length === 0) {
    container.replaceChildren(
      h('span', { class: 'prov-empty', text: 'No files' })
    );
    return;
  }

  const thead = h('thead', null,
    h('tr', null, ...columns.map(c => h('th', { text: c.label })))
  );

  const tbody = h('tbody');
  for (const f of files) {
    const tr = h('tr');
    for (const c of columns) {
      const raw = f[c.key];
      const props = {};
      if (raw == null || raw === '') {
        props.text = '';
      } else if (c.format === 'bytes') {
        props.class = 'prov-num';
        props.text = fmt.bytes(raw);
      } else if (c.format === 'hash') {
        props.class = 'mono';
        props.title = String(raw);
        props.text = String(raw).slice(0, 12) + '…';
      } else {
        props.text = String(raw);
      }
      tr.append(h('td', props));
    }
    tbody.append(tr);
  }

  container.replaceChildren(h('table', { class: 'prov-table' }, thead, tbody));
}

// License package breakdown

function renderLicensePackages(container, packages, licensePolicy) {
  if (!container) return;

  if (!packages || packages.length === 0) {
    container.replaceChildren(
      h('span', { class: 'prov-empty', text: 'No packages' })
    );
    return;
  }

  // group by license
  const byLicense = {};
  packages.forEach(pkg => {
    const lic = pkg.license || '(no license)';
    if (!byLicense[lic]) byLicense[lic] = { packages: [], status: pkg.license_status };
    byLicense[lic].packages.push(pkg);
  });

  // sort: denied first, then unknown, then allowed
  const statusOrder = { denied: 0, unknown: 1, allowed: 2 };
  const sorted = Object.entries(byLicense).sort((a, b) => {
    const oa = statusOrder[a[1].status] ?? 1;
    const ob = statusOrder[b[1].status] ?? 1;
    return oa !== ob ? oa - ob : a[0].localeCompare(b[0]);
  });

  container.replaceChildren();

  for (const [license, info] of sorted) {
    const state = info.status === 'allowed' ? 'good' : info.status === 'denied' ? 'bad' : 'warn';
    const details = h('details', { class: 'prov-licgroup' });

    // summary row: status glyph (a11y, not color-alone) + license + count + chevron
    const summary = h('summary', null,
      h('span', { class: 'prov-licgroup__lead' },
        h('span', { class: 'prov-glyph prov-glyph--' + state, text: statusGlyph(info.status) }),
        h('span', { class: 'mono', text: license }),
        h('span', { class: 'prov-muted', text: info.packages.length + ' package' + (info.packages.length !== 1 ? 's' : '') })
      ),
      chevronSvg('prov-licgroup__chev')
    );

    details.append(summary);

    // package rows inside the details
    const pkgList = h('div', { class: 'prov-licgroup__body' });
    for (const pkg of info.packages) {
      pkgList.append(
        h('div', { class: 'prov-licrow' },
          h('span', { class: 'mono', text: pkg.name }),
          h('span', { class: 'mono prov-muted', text: pkg.version })
        )
      );
    }
    details.append(pkgList);

    container.append(details);
  }
}

// helper: status -> license text color class
function statusTextClass(status) {
  switch (status) {
    case 'allowed': return 'prov-good';
    case 'denied': return 'prov-bad';
    default: return 'prov-warn';
  }
}

// helper: status -> glyph marker (non-color status cue; a11y)
function statusGlyph(status) {
  switch (status) {
    case 'allowed': return '✓';
    case 'denied': return '✗';
    default: return '·';
  }
}

// Content provenance section

async function initContent() {
  const container = document.getElementById('provenance-content');
  if (!container) return;

  const apiData = readInlineJSON('provenance-content-data') || await fetchJSON(API.content);

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
      // compose a commit URL so the [git] anchor can data-bind-href directly
      source: apiData.bundle?.source ? {
        ...apiData.bundle.source,
        commit_url: apiData.bundle.source.repository && apiData.bundle.source.commit
          ? `${apiData.bundle.source.repository}/commit/${apiData.bundle.source.commit}`
          : undefined
      } : undefined,
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

  // content bundle file inventory (collapsed in the evidence ledger)
  renderFileTable(document.getElementById('content-file-list'), apiData.bundle?.files, [
    { key: 'path', label: 'path' },
    { key: 'type', label: 'type' },
    { key: 'size', label: 'size', format: 'bytes' },
    { key: 'sha256', label: 'sha-256', format: 'hash' }
  ]);
}

// App provenance section

async function initApp() {
  const container = document.getElementById('provenance-app');
  if (!container) return;

  const apiData = readInlineJSON('provenance-app-data') || await fetchJSON(API.app);

  if (!apiData) {
    const dot = container.querySelector('[data-bind="app.status-dot"]');
    const text = container.querySelector('[data-bind="app.status-text"]');
    if (dot) dot.classList.add('status-dot--bad');
    if (text) text.textContent = 'Unavailable';
    return;
  }

  // normalize full endpoint structure to match what templates expect
  const rel = apiData.release || {};
  const summary = rel.summary || {};
  const vulns = summary.vulnerabilities || {};
  // top-level signing is the runtime-reconciled view
  // release.summary.signing is the build-time claim
  const signing = apiData.signing || summary.signing || {};
  const signatures = apiData.signatures || {};
  const artifact = rel.artifacts?.[0] || {};

  const data = {
    app: {
      version: rel.version || apiData.build?.version,
      track: rel.track,
      build_id: rel.build_id,
      release_id: rel.release_id,
      created_at: rel.created_at,
      fetched_at: apiData.fetched_at,
      build_actor: apiData.build?.build_actor,
      build_system: apiData.build?.build_system,
      build_run_url: apiData.build?.build_run_url,
      build_run_id: apiData.build?.build_run_id,
      builder_identity: apiData.build?.builder_identity,
      go_version: apiData.build?.go_version,
      'status-text': vulns.gate_result === 'pass' ? 'Verified' : 'Warning',
      source: {
        repository: rel.source?.repo,
        commit: rel.source?.commit,
        commit_short: rel.source?.commit_short,
        commit_date: rel.source?.commit_date,
        branch: rel.source?.branch,
        commit_url: rel.source?.repo && rel.source?.commit
          ? `${rel.source.repo}/commit/${rel.source.commit}`
          : undefined,
        tag: rel.source?.base_tag,
        dirty: rel.source?.dirty
      },
      builder: {
        repository: rel.builder?.repo,
        branch: rel.builder?.branch,
        commit: rel.builder?.commit,
        commit_short: rel.builder?.commit_short,
        commit_date: rel.builder?.commit_date,
        dirty: rel.builder?.dirty
      },
      signing: signing,
      signatures: signatures,
      tooling: apiData.tooling || {},
      trusted_root_url: apiData.trusted_root_url,
      attestations: apiData.attestations || {},
      policy: apiData.policy || {},
      vulnerabilities: {
        ...vulns,
        counts: vulns.counts || {}
      },
      sbom: summary.sbom || {},
      licenses: apiData.licenses || {},
      evidence: {
        file_count: apiData.evidence?.file_count,
        categories: apiData.evidence?.categories,
        completeness: summary.evidence_completeness || {}
      },
      binary: {
        sha256: artifact.binary?.sha256,
        size: artifact.binary?.size
      },
      container: {
        repository: rel.oci?.repository,
        tag: rel.oci?.tag,
        digest: rel.oci?.digest,
        digest_ref: rel.oci?.digest_ref,
        media_type: rel.oci?.mediaType,
        artifact_type: rel.oci?.artifactType,
        pushed_at: rel.oci?.pushed_at,
        os: artifact.os,
        arch: artifact.arch,
        platform: artifact.os && artifact.arch ? artifact.os + '/' + artifact.arch : '—'
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
  if (scannerEl && vulns.by_scanner) {
    renderScannerBreakdown(scannerEl, vulns.by_scanner);
  }

  // render individual findings
  const findingsEl = document.getElementById('vuln-findings-list');
  if (findingsEl && vulns.findings) {
    renderFindings(findingsEl, vulns.findings);
  }

  // render denied_found
  const deniedEl = document.getElementById('denied-found-list');
  if (deniedEl && apiData.licenses?.denied_found?.length > 0) {
    deniedEl.replaceChildren();
    for (const lic of apiData.licenses.denied_found) {
      deniedEl.append(h('span', { class: 'prov-chip prov-chip--bad' },
        h('span', { class: 'prov-chip__glyph prov-glyph--bad', text: '✗' }),
        h('span', { class: 'prov-chip__name', text: lic })
      ));
    }
  }

  // render package list
  const pkgList = document.getElementById('sbom-package-list');
  if (pkgList && apiData.packages) {
    renderPackageList(pkgList, apiData.packages);
  }

  // render license package breakdown
  const licPkgList = document.getElementById('license-package-list');
  if (licPkgList && apiData.packages) {
    renderLicensePackages(licPkgList, apiData.packages, apiData.policy?.license);
  }

  // render attestation + evidence file inventories (collapsed in the ledger)
  const evidenceCols = [
    { key: 'path', label: 'path' },
    { key: 'category', label: 'category' },
    { key: 'scope', label: 'scope' },
    { key: 'size', label: 'size', format: 'bytes' },
    { key: 'sha256', label: 'sha-256', format: 'hash' }
  ];
  renderFileTable(document.getElementById('attestation-file-list'), apiData.attestations?.files, evidenceCols);
  renderFileTable(document.getElementById('evidence-file-list'), apiData.evidence?.files, evidenceCols);
}

// init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initContent();
  initApp();
});

})();

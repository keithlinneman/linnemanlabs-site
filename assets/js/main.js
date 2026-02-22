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
  appSummary: '/api/provenance/app/summary',
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

// fetch JSON (memoized per page load - deduplicates concurrent calls to same URL)
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

    el.replaceChildren();

    if (Array.isArray(value)) {
      if (value.length === 0) {
        el.append(h('span', { class: 'text-xs text-[rgb(var(--muted))]', text: 'None' }));
      } else {
        value.forEach(item => {
          el.append(
            h('span', { class: 'text-xs px-2 py-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]' },
              h('span', { class: 'text-[rgb(var(--accent))]', text: String(item) })
            )
          );
        });
      }
    } else if (typeof value === 'object') {
      for (const [type, count] of Object.entries(value)) {
        el.append(
          h('span', { class: 'text-xs px-2 py-1 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]' },
            h('span', { class: 'text-[rgb(var(--accent))]', text: type }),
            h('span', { class: 'text-[rgb(var(--muted))] ml-1', text: String(count) })
          )
        );
      }
    }
  });
}

// Vulnerability rendering - severity badges, scanner breakdown, findings list

const SEV_CLASSES = {
  critical:   'bg-[rgb(var(--bad))]/20 text-[rgb(var(--bad))]',
  high:       'bg-[rgb(var(--warn))]/20 text-[rgb(var(--warn))]',
  medium:     'bg-[rgb(var(--accent))]/20 text-[rgb(var(--accent))]',
  low:        'bg-[rgb(var(--muted))]/20 text-[rgb(var(--muted))]',
  negligible: 'bg-[rgb(var(--muted))]/10 text-[rgb(var(--muted))]',
  unknown:    'bg-[rgb(var(--muted))]/10 text-[rgb(var(--muted))]'
};

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'];

// render per-scanner vulnerability breakdown
function renderScannerBreakdown(container, byScanner) {
  if (!container || !byScanner) return;
  container.replaceChildren();

  for (const [scanner, results] of Object.entries(byScanner)) {
    const row = h('div', { class: 'flex items-center justify-between p-2 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]' },
      h('span', { class: 'text-xs font-medium mono w-28', text: scanner })
    );

    if ('findings' in results) {
      const content = h('div', { class: 'flex items-center gap-3' },
        h('span', { class: 'text-sm', text: results.findings + ' finding' + (results.findings !== 1 ? 's' : '') })
      );

      if (results.vuln_ids && results.vuln_ids.length > 0) {
        const ids = h('span', { class: 'text-xs' });
        results.vuln_ids.forEach((id, i) => {
          if (i > 0) ids.append(', ');
          ids.append(h('span', { class: 'text-[rgb(var(--accent))]', text: id }));
        });
        content.append(ids);
      }
      row.append(content);
    } else {
      const grid = h('div', { class: 'flex gap-2' });
      for (const s of SEV_ORDER) {
        grid.append(
          h('div', { class: 'text-center' },
            h('div', { class: 'w-7 h-7 rounded flex items-center justify-center text-xs font-medium ' + SEV_CLASSES[s], text: String(results[s] || 0) }),
            h('div', { class: 'text-[9px] text-[rgb(var(--muted))] mt-0.5', text: s.charAt(0).toUpperCase() })
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
      h('span', { class: 'text-xs text-[rgb(var(--good))]', text: 'No findings' })
    );
    return;
  }

  container.replaceChildren();

  for (const f of findings) {
    const cls = SEV_CLASSES[f.severity] || SEV_CLASSES.unknown;

    // header row: severity badge + id (left), scanner badges (right)
    const left = h('div', { class: 'flex items-center gap-2 min-w-0' },
      h('span', { class: 'shrink-0 text-[10px] font-medium uppercase px-1.5 py-0.5 rounded ' + cls, text: f.severity })
    );

    if (f.source_url) {
      left.append(h('a', {
        class: 'mono text-sm font-medium text-[rgb(var(--accent))] hover:underline truncate',
        href: f.source_url, target: '_blank', rel: 'noopener', text: f.id
      }));
    } else {
      left.append(h('span', { class: 'mono text-sm font-medium truncate', text: f.id }));
    }

    const right = h('div', { class: 'flex gap-1 shrink-0' });
    for (const s of f.scanners) {
      right.append(h('span', {
        class: 'text-[10px] px-1.5 py-0.5 rounded border border-[rgb(var(--border))] text-[rgb(var(--muted))]',
        text: s
      }));
    }

    const card = h('div', { class: 'p-3 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))]' },
      h('div', { class: 'flex items-start justify-between gap-3' }, left, right)
    );

    // optional title
    if (f.title) {
      const truncated = f.title.length > 120 ? f.title.substring(0, 120) + '...' : f.title;
      card.append(h('div', { class: 'text-xs text-[rgb(var(--muted))] mt-1.5 line-clamp-2', text: truncated }));
    }

    // metadata: package, installed, fixed
    const meta = h('div', { class: 'flex flex-wrap gap-x-4 gap-y-1 mt-2 text-[11px]' },
      h('div', null,
        h('span', { class: 'text-[rgb(var(--muted))]', text: 'Package: ' }),
        h('span', { class: 'mono', text: f.package || '—' })
      ),
      h('div', null,
        h('span', { class: 'text-[rgb(var(--muted))]', text: 'Installed: ' }),
        h('span', { class: 'mono', text: f.installed_version || '—' })
      )
    );

    if (f.fixed_version) {
      meta.append(
        h('div', null,
          h('span', { class: 'text-[rgb(var(--muted))]', text: 'Fixed: ' }),
          h('span', { class: 'mono text-[rgb(var(--good))]', text: f.fixed_version })
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
      h('span', { class: 'text-xs text-[rgb(var(--muted))]', text: 'No packages' })
    );
    return;
  }

  const list = h('div', { class: 'space-y-1' });

  for (const pkg of packages) {
    list.append(
      h('div', { class: 'flex items-center justify-between py-1.5 px-2 rounded border border-[rgb(var(--border))] bg-[rgb(var(--bg))] text-xs' },
        h('div', { class: 'flex-1 min-w-0' },
          h('span', { class: 'mono text-[rgb(var(--fg))] break-all', text: pkg.name })
        ),
        h('div', { class: 'flex items-center gap-3 ml-3 shrink-0' },
          h('span', { class: 'mono text-[rgb(var(--muted))]', text: pkg.version }),
          h('span', { class: 'w-16 text-right ' + statusColor(pkg.license_status), text: pkg.license || 'none' })
        )
      )
    );
  }

  container.replaceChildren(list);
}

// License package breakdown

function renderLicensePackages(container, packages, licensePolicy) {
  if (!container) return;

  if (!packages || packages.length === 0) {
    container.replaceChildren(
      h('span', { class: 'text-xs text-[rgb(var(--muted))]', text: 'No packages' })
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
    const details = h('details', { class: 'group border border-[rgb(var(--border))] rounded bg-[rgb(var(--bg))]' });

    // summary row
    const summary = h('summary', { class: 'flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-[rgb(var(--panel))] transition-colors' },
      h('div', { class: 'flex items-center gap-2' },
        h('span', { class: 'w-2 h-2 rounded-full ' + statusDot(info.status) }),
        h('span', { class: 'text-sm font-medium mono', text: license }),
        h('span', { class: 'text-xs text-[rgb(var(--muted))]', text: info.packages.length + ' package' + (info.packages.length !== 1 ? 's' : '') })
      ),
      chevronSvg('w-3 h-3 text-[rgb(var(--muted))] transition-transform group-open:rotate-180')
    );

    details.append(summary);

    // package rows inside the details
    const pkgList = h('div', { class: 'border-t border-[rgb(var(--border))] px-3 py-2 space-y-1' });
    for (const pkg of info.packages) {
      pkgList.append(
        h('div', { class: 'flex items-center justify-between text-xs py-0.5' },
          h('span', { class: 'mono text-[rgb(var(--fg))] break-all', text: pkg.name }),
          h('span', { class: 'mono text-[rgb(var(--muted))] ml-2 shrink-0', text: pkg.version })
        )
      );
    }
    details.append(pkgList);

    container.append(details);
  }
}

// helper: status color for license text
function statusColor(status) {
  switch (status) {
    case 'allowed': return 'text-[rgb(var(--good))]';
    case 'denied': return 'text-[rgb(var(--bad))]';
    default: return 'text-[rgb(var(--warn))]';
  }
}

// helper: status dot class for license grouping
function statusDot(status) {
  switch (status) {
    case 'allowed': return 'bg-[rgb(var(--good))]';
    case 'denied': return 'bg-[rgb(var(--bad))]';
    default: return 'bg-[rgb(var(--warn))]';
  }
}

// Header provenance dropdown

async function initHeader() {
  const container = document.getElementById('header-provenance');
  if (!container) return;

  const dot = document.getElementById('hdr-status-dot');
  const versionEl = document.getElementById('hdr-version');
  const commitEl = document.getElementById('hdr-commit');

  const [appData, contentData] = await Promise.all([
    fetchJSON(API.appSummary),
    fetchJSON(API.contentSummary)
  ]);

  // handle total failure
  if (!appData && !contentData) {
    if (dot) dot.classList.add('status-dot--bad');
    if (versionEl) versionEl.textContent = '—';
    if (commitEl) commitEl.textContent = 'unavailable';
    return;
  }

  // populate button - no 'v' prefix, version string already includes it if needed
  if (appData) {
    if (versionEl) versionEl.textContent = appData.version || '—';
    if (commitEl) commitEl.textContent = appData.source?.commit_short || '—';

    // status dot: green if no criticals, red if criticals, warn if gate fails
    const vulns = appData.vulnerabilities || {};
    const critCount = vulns.counts?.critical ?? 0;
    if (dot) {
      if (critCount > 0) {
        dot.classList.add('status-dot--bad');
      } else if (vulns.gate_result && vulns.gate_result !== 'pass') {
        dot.classList.add('status-dot--warn');
      }
    }
  }

  // build the data object for binding
  const vulns = appData?.vulnerabilities || {};
  const signing = appData?.signing || {};
  const attestations = appData?.attestations || {};
  const policy = appData?.policy || {};

  // try multiple paths for OCI data - summary endpoint may structure differently
  const oci = appData?.oci || appData?.release?.oci || appData?.components?.[0]?.oci || {};

  const data = {
    hdr: {
      app: {
        version: appData?.version || '—',
        track: appData?.track || '—',
        build_id: appData?.build_id || '—',
        created_at: appData?.created_at || '—',
        source: {
          commit_short: appData?.source?.commit_short || '—',
          commit_date: appData?.source?.commit_date || '—',
          dirty: appData?.source?.dirty || false
        },
        vulns: {
          critical: vulns.counts?.critical ?? '—',
          high: vulns.counts?.high ?? '—',
          medium: vulns.counts?.medium ?? '—',
          low: vulns.counts?.low ?? '—',
          gate_result: vulns.gate_result || '—'
        },
        signing: {
          cosign: signing.artifacts_attested || false,
          inventory: signing.inventory_signed || false,
          release: signing.release_signed || false
        },
        attestations: {
          sbom: attestations.sbom_attested || false,
          scan: attestations.scan_attested || false,
          license: attestations.license_attested || false
        },
        policy: {
          signing_required: policy.signing?.require_inventory_signature || policy.signing?.require_subject_signatures || false,
          sbom_required: policy.evidence?.sbom_required || false,
          scan_required: policy.evidence?.scan_required || false,
          vuln_gating: (policy.vulnerability?.block_on && policy.vulnerability.block_on.length > 0) || false,
          license_gating: (policy.license?.denied && policy.license.denied.length > 0) || !policy.license?.allow_unknown || false,
          provenance_required: policy.evidence?.provenance_required || false
        },
        container: {
          ref: oci.registry && oci.repository && oci.tag
            ? oci.registry + '/' + oci.repository + ':' + oci.tag
            : oci.repository && oci.tag
              ? oci.repository + ':' + oci.tag
              : '—',
          digest_short: oci.digest
            ? oci.digest.substring(0, 24) + '...'
            : '—',
          pushed_at: oci.pushed_at || '—'
        }
      },
      content: {
        version: contentData?.version || '—',
        created_at: contentData?.created_at || '—',
        total_files: contentData?.total_files ?? '—',
        total_size: contentData?.total_size ?? 0,
        content_hash_short: contentData?.content_hash
          ? 'sha256:' + contentData.content_hash.substring(0, 16) + '...'
          : '—'
      }
    }
  };

  bindData(container, data);
}

// Content provenance section

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

// App provenance section

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

  // normalize full endpoint structure to match what templates expect
  const rel = apiData.release || {};
  const summary = rel.summary || {};
  const vulns = summary.vulnerabilities || {};
  const signing = summary.signing || {};
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
      builder_identity: apiData.build?.builder_identity,
      go_version: apiData.build?.go_version,
      'status-text': vulns.gate_result === 'pass' ? 'Verified' : 'Warning',
      source: {
        repository: rel.source?.repo,
        commit: rel.source?.commit,
        commit_short: rel.source?.commit_short,
        commit_date: rel.source?.commit_date,
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
      deniedEl.append(h('span', {
        class: 'text-xs px-2 py-1 rounded border border-[rgb(var(--bad))]/50 bg-[rgb(var(--bad))]/10 text-[rgb(var(--bad))]',
        text: lic
      }));
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
}

// Footer

async function initFooter() {
  const container = document.getElementById('content-provenance-footer');
  if (!container) return;

  const [data, appData] = await Promise.all([
    fetchJSON(API.contentSummary),
    fetchJSON(API.appSummary)
  ]);

  // populate footer version spans
  const appVer = document.getElementById('footer-app-version');
  const contentVer = document.getElementById('footer-content-version');
  if (appVer) appVer.textContent = appData?.version || '—';
  if (contentVer) contentVer.textContent = data?.version || '—';
  
  if (!data) {
    container.replaceChildren(
      h('div', { class: 'flex items-center gap-2' },
        h('span', { class: 'status-dot status-dot--warn' }),
        h('span', { class: 'text-xs text-[rgb(var(--muted))]', text: 'Content provenance unavailable' })
      )
    );
    return;
  }

  const grid = h('div', { class: 'grid gap-2' },
    h('div', null,
      h('div', { class: 'attestation-label', text: 'Content Version' }),
      h('div', { class: 'attestation-value tabular', text: data.version || '—' })
    ),
    h('div', null,
      h('div', { class: 'attestation-label', text: 'Bundle SHA256' }),
      h('div', { class: 'attestation-value text-xs', text: data.content_hash || '—' })
    ),
    h('div', { class: 'flex gap-6' },
      h('div', null,
        h('div', { class: 'attestation-label', text: 'Generated' }),
        h('div', { class: 'attestation-value tabular', text: fmt.date(data.created_at) })
      ),
      h('div', null,
        h('div', { class: 'attestation-label', text: 'Files' }),
        h('div', { class: 'attestation-value tabular', text: String(data.total_files || '—') })
      ),
      h('div', null,
        h('div', { class: 'attestation-label', text: 'Size' }),
        h('div', { class: 'attestation-value tabular', text: fmt.bytes(data.total_size) })
      )
    )
  );

  container.replaceChildren(
    h('div', { class: 'text-[rgb(var(--fg))] font-medium mb-1', text: 'Content Provenance' }),
    h('div', { class: 'text-xs text-[rgb(var(--muted))] mb-3', text: 'Content bundle verified from ' + (data.source || 'unknown') + ' source.' }),
    grid,
    h('div', { class: 'mt-3 pt-3 border-t border-[rgb(var(--border))]' },
      h('a', { class: 'text-xs text-[rgb(var(--accent))] hover:underline', href: '/about/provenance/', text: 'View full provenance details →' })
    )
  );
}

// init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initHeader();
  initFooter();
  initContent();
  initApp();
});
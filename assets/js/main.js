// main.js - site-wide. Only the header/footer provenance "verified" status.
// The heavy provenance-page rendering lives in provenance.js, loaded only on /about/provenance/*.
// Wrapped in an IIFE so nothing leaks to the global scope (and can't collide with provenance.js).
(function () {

const API = {
  contentSummary: '/api/provenance/content/summary',
  appSummary: '/api/provenance/app/summary'
};

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

// Header: content version + "verified" link (keys off id="header-provenance").
async function initHeader() {
  const container = document.getElementById('header-provenance');
  if (!container) return;

  const contentData = await fetchJSON(API.contentSummary);

  const versionEl = container.querySelector('[data-bind="hdr.content.version"]');
  if (versionEl) versionEl.textContent = contentData?.version || '—';

  const verifiedLink = container.querySelector('[data-bind-show="hdr.content.verified"]');
  if (verifiedLink) {
    const verified = !!contentData && (contentData.verified ?? contentData.signed ?? !!contentData.content_hash);
    verifiedLink.classList.toggle('hidden', !verified);
  }
}

// Footer: app + content version spans.
async function initFooter() {
  const [data, appData] = await Promise.all([
    fetchJSON(API.contentSummary),
    fetchJSON(API.appSummary)
  ]);

  const appVer = document.getElementById('footer-app-version');
  const contentVer = document.getElementById('footer-content-version');
  if (appVer) appVer.textContent = appData?.version || '—';
  if (contentVer) contentVer.textContent = data?.version || '—';
}

// init on DOM ready
document.addEventListener('DOMContentLoaded', () => {
  initHeader();
  initFooter();
});

})();

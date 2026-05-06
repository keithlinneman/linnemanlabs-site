(function () {
  'use strict';

  // Watches h2/h3 inside the prose, marks the matching TOC link(s) active.
  function initScrollspy() {
    const tocLinks = document.querySelectorAll('.post-toc a[href^="#"]');
    if (tocLinks.length === 0) return;

    // Mobile <details> TOC and desktop rail TOC share hrefs; track all links per id.
    const linksById = new Map();
    tocLinks.forEach(a => {
      const id = decodeURIComponent(a.getAttribute('href').slice(1));
      if (!id) return;
      if (!linksById.has(id)) linksById.set(id, []);
      linksById.get(id).push(a);
    });

    const headings = Array.from(linksById.keys())
      .map(id => document.getElementById(id))
      .filter(Boolean);
    if (headings.length === 0) return;

    let active = null;
    function setActive(id) {
      if (active === id) return;
      tocLinks.forEach(a => a.classList.remove('toc-active'));
      const links = linksById.get(id) || [];
      links.forEach(a => a.classList.add('toc-active'));
      active = id;
    }

    // Click: instant feedback, before observer events from the scroll arrive.
    tocLinks.forEach(a => {
      a.addEventListener('click', () => {
        const id = decodeURIComponent(a.getAttribute('href').slice(1));
        if (id && linksById.has(id)) setActive(id);
      });
    });

    // Intersection zone is the top 25% of the viewport, including the very top
    // edge, so a heading scrolled to top: 0 still counts as visible.
    const intersecting = new Set();
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) intersecting.add(e.target);
        else intersecting.delete(e.target);
      });

      // Topmost (document-order) heading currently in the zone wins.
      for (const h of headings) {
        if (intersecting.has(h)) { setActive(h.id); return; }
      }

      // No heading in zone: highlight the last one whose top has scrolled above
      // the viewport (we're reading content within that section).
      let candidate = null;
      for (const h of headings) {
        if (h.getBoundingClientRect().top < 1) candidate = h.id;
        else break;
      }
      if (candidate) setActive(candidate);
    }, {
      rootMargin: '0px 0px -75% 0px',
      threshold: 0
    });

    headings.forEach(h => io.observe(h));
  }

  // PhotoSwipe
  // PhotoSwipe and PhotoSwipeLightbox UMD scripts are loaded before this file.
  function initPhotoSwipe() {
    if (typeof PhotoSwipeLightbox === 'undefined' || typeof PhotoSwipe === 'undefined') return;
    const links = document.querySelectorAll('article a[data-pswp-width]');
    if (links.length === 0) return;

    const lb = new PhotoSwipeLightbox({
      gallery: 'article',
      children: 'a[data-pswp-width]',
      pswpModule: PhotoSwipe
    });
    lb.init();
  }

  function ready() {
    initScrollspy();
    initPhotoSwipe();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ready);
  } else {
    ready();
  }
})();

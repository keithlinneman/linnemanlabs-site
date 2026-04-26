// Post-page enhancements: TOC scrollspy + PhotoSwipe init.
// Loaded only on post single pages via the {{ block "scripts" }} hook.

(function () {
  'use strict';

  // TOC scrollspy
  // Watches h2/h3 inside the prose, marks the matching TOC link active.
  function initScrollspy() {
    const tocLinks = document.querySelectorAll('.post-toc a[href^="#"]');
    if (tocLinks.length === 0) return;

    const linkById = new Map();
    tocLinks.forEach(a => {
      const id = decodeURIComponent(a.getAttribute('href').slice(1));
      if (id) linkById.set(id, a);
    });

    const headings = Array.from(linkById.keys())
      .map(id => document.getElementById(id))
      .filter(Boolean);
    if (headings.length === 0) return;

    let active = null;
    function setActive(id) {
      if (active === id) return;
      tocLinks.forEach(a => a.classList.remove('toc-active'));
      const link = linkById.get(id);
      if (link) link.classList.add('toc-active');
      active = id;
    }

    const visible = new Set();
    const io = new IntersectionObserver((entries) => {
      entries.forEach(e => {
        if (e.isIntersecting) visible.add(e.target.id);
        else visible.delete(e.target.id);
      });

      if (visible.size > 0) {
        // pick the topmost visible heading in document order
        for (const h of headings) {
          if (visible.has(h.id)) { setActive(h.id); break; }
        }
      } else {
        // none visible: pick the last heading whose top is above the viewport
        let candidate = null;
        for (const h of headings) {
          if (h.getBoundingClientRect().top < 80) candidate = h.id;
          else break;
        }
        if (candidate) setActive(candidate);
      }
    }, {
      rootMargin: '-72px 0px -60% 0px',
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

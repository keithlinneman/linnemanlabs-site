(function () {
  'use strict';

  // TOC: highlight the link for the heading currently near the top.
  // The TOC is hidden on mobile, so a single IntersectionObserver is enough.
  function initScrollspy() {
    const links = {};
    document.querySelectorAll('.toc a[href^="#"]').forEach(a => {
      const id = decodeURIComponent(a.getAttribute('href').slice(1));
      if (id) links[id] = a;
    });
    if (Object.keys(links).length === 0) return;

    const spy = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting && links[e.target.id]) {
          Object.values(links).forEach(a => a.classList.remove('active'));
          links[e.target.id].classList.add('active');
        }
      });
    }, { rootMargin: '0px 0px -75% 0px' });

    document.querySelectorAll('.post-body h2[id], .post-body h3[id]').forEach(h => {
      if (links[h.id]) spy.observe(h);
    });
  }

  // PhotoSwipe lightbox for content images (UMD scripts load before this file).
  function initPhotoSwipe() {
    if (typeof PhotoSwipeLightbox === 'undefined' || typeof PhotoSwipe === 'undefined') return;
    const links = document.querySelectorAll('article a[data-pswp-width]');
    if (links.length === 0) return;

    const lb = new PhotoSwipeLightbox({
      gallery: '.fig',
      children: 'a[data-pswp-width]',
      pswpModule: PhotoSwipe,
      bgClickAction: 'close',
      // imageClickAction: 'close',
      tapAction: 'zoom-or-close',
      wheelToZoom: false
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

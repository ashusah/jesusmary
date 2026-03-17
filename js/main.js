/* ═══════════════════════════════════════════════
   main.js — Shared JS for all pages
   Handles: Navbar, Footer, Animations, Scroll
═══════════════════════════════════════════════ */

/* ──────────────────────────────────────────────
   1. NAVBAR HTML — injected into every page
──────────────────────────────────────────────── */
function renderNavbar() {
  const navbar = document.getElementById('navbar');
  if (!navbar) return;

  navbar.innerHTML = `
    <a class="nav-brand" href="index.html">
      <img src="images/logo.png" alt="Jesus & Mary's Nursery Logo" class="nav-logo">
      <div class="nav-school-name">
        Jesus &amp; Mary's Nursery
        <span>Knowledge · Truth · Faith</span>
      </div>
    </a>

    <ul class="nav-links" id="navLinks">
      <li><a href="index.html"    data-page="index">Home</a></li>
      <li><a href="about.html"    data-page="about">About</a></li>
      <li><a href="programs.html" data-page="programs">Programs</a></li>
      <li><a href="gallery.html"  data-page="gallery">Gallery</a></li>
      <li><a href="contact.html"  data-page="contact" class="nav-cta">Enquire Now</a></li>
    </ul>

    <div class="hamburger" id="hamburger" aria-label="Toggle menu">
      <span></span><span></span><span></span>
    </div>

    <div class="mobile-menu" id="mobileMenu">
      <a href="index.html"    data-page="index">Home</a>
      <a href="about.html"    data-page="about">About</a>
      <a href="programs.html" data-page="programs">Programs</a>
      <a href="gallery.html"  data-page="gallery">Gallery</a>
      <a href="contact.html"  data-page="contact" class="nav-cta">Enquire Now</a>
    </div>
  `;

  setActiveNavLink();
  initHamburger();
}

/* ──────────────────────────────────────────────
   2. FOOTER HTML — injected into every page
──────────────────────────────────────────────── */
function renderFooter() {
  const footer = document.getElementById('footer');
  if (!footer) return;

  footer.innerHTML = `
    <div class="footer-inner">
      <div class="footer-grid">

        <div class="footer-brand">
          <div class="footer-brand-logo">
            <img src="images/logo.png" alt="Logo" class="footer-logo-circle" style="padding:2px;">
            <div class="footer-brand-name">
              Jesus &amp; Mary's Nursery
              <span>Knowledge · Truth · Faith</span>
            </div>
          </div>
          <p>A place where little hearts grow big dreams. Providing quality early childhood education with love, care, and strong values since our founding.</p>
        </div>

        <div class="footer-col">
          <h4>Quick Links</h4>
          <ul>
            <li><a href="index.html">Home</a></li>
            <li><a href="about.html">About Us</a></li>
            <li><a href="programs.html">Programs</a></li>
            <li><a href="gallery.html">Gallery</a></li>
            <li><a href="contact.html">Contact Us</a></li>
          </ul>
        </div>

        <div class="footer-col">
          <h4>Programs</h4>
          <ul>
            <li><a href="programs.html">Play Group</a></li>
            <li><a href="programs.html">Nursery</a></li>
            <li><a href="programs.html">LKG</a></li>
            <li><a href="programs.html">UKG</a></li>
            <li><a href="programs.html">Summer Camp</a></li>
          </ul>
        </div>

        <div class="footer-col">
          <h4>Contact</h4>
          <div class="footer-contact-item">
            <span class="fc-icon">📍</span>
            <p>Bunglow Nr 93, Opp Swarg Mandir<br>Mhow, MP – 453441</p>
          </div>
          <div class="footer-contact-item">
            <span class="fc-icon">📞</span>
            <p>+91 93294 81454</p>
          </div>
          <div class="footer-contact-item">
            <span class="fc-icon">🕐</span>
            <p>Mon–Sat: 9:15AM – 12:30PM</p>
          </div>
          <a class="footer-social-link" href="https://instagram.com/jesusandmary_nursery_school" target="_blank" rel="noopener noreferrer" aria-label="Follow Jesus and Mary Nursery School on Instagram">
            <svg viewBox="0 0 24 24" aria-hidden="true" focusable="false">
              <path d="M7.8 2h8.4A5.8 5.8 0 0 1 22 7.8v8.4a5.8 5.8 0 0 1-5.8 5.8H7.8A5.8 5.8 0 0 1 2 16.2V7.8A5.8 5.8 0 0 1 7.8 2Zm-.2 2A3.6 3.6 0 0 0 4 7.6v8.8A3.6 3.6 0 0 0 7.6 20h8.8a3.6 3.6 0 0 0 3.6-3.6V7.6A3.6 3.6 0 0 0 16.4 4H7.6Zm9.45 1.5a1.15 1.15 0 1 1 0 2.3 1.15 1.15 0 0 1 0-2.3ZM12 7a5 5 0 1 1 0 10 5 5 0 0 1 0-10Zm0 2a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z"/>
            </svg>
            <span>@jesusandmary_nursery_school</span>
          </a>
        </div>

      </div>
      <div class="footer-bottom">
        <p>© ${new Date().getFullYear()} Jesus &amp; Mary's Nursery School. All rights reserved.</p>
        <div class="footer-motto">
          <span>⭐ Knowledge</span>
          <span>⭐ Truth</span>
          <span>⭐ Faith</span>
        </div>
      </div>
    </div>
  `;
}

/* ──────────────────────────────────────────────
   3. ACTIVE NAV LINK — highlights current page
──────────────────────────────────────────────── */
function setActiveNavLink() {
  const page = document.body.getAttribute('data-page') || '';
  document.querySelectorAll('[data-page]').forEach(link => {
    if (link.getAttribute('data-page') === page) {
      link.classList.add('active');
    }
  });
}

/* ──────────────────────────────────────────────
   4. HAMBURGER MENU — mobile toggle
──────────────────────────────────────────────── */
function initHamburger() {
  const hamburger  = document.getElementById('hamburger');
  const mobileMenu = document.getElementById('mobileMenu');
  if (!hamburger || !mobileMenu) return;

  hamburger.addEventListener('click', () => {
    mobileMenu.classList.toggle('open');
  });

  // close on outside click
  document.addEventListener('click', (e) => {
    if (!hamburger.contains(e.target) && !mobileMenu.contains(e.target)) {
      mobileMenu.classList.remove('open');
    }
  });
}

/* ──────────────────────────────────────────────
   5. SCROLL ANIMATIONS — fade-in on scroll
──────────────────────────────────────────────── */
function initScrollAnimations() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
      }
    });
  }, { threshold: 0.1 });

  document.querySelectorAll('.fade-in').forEach(el => observer.observe(el));
}

/* ──────────────────────────────────────────────
   6. SMOOTH SCROLL — for same-page hash links
──────────────────────────────────────────────── */
function initSmoothScroll() {
  document.querySelectorAll('a[href^="#"]').forEach(link => {
    link.addEventListener('click', e => {
      const target = document.querySelector(link.getAttribute('href'));
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });
}

/* ──────────────────────────────────────────────
   7. INIT — run everything on DOM ready
──────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  renderNavbar();
  renderFooter();
  initScrollAnimations();
  initSmoothScroll();
});

# Jesus & Mary's Nursery School Website

This repository contains a static, multi-page school website built with plain HTML, CSS, and JavaScript.

## Tech Stack
- **HTML** for page structure
- **CSS** for shared and page-specific styling
- **Vanilla JavaScript** for reusable layout injection (navbar/footer), animations, and form validation
- **Static assets** (images + one video) under `images/`

## Pages
- `index.html` — landing page with hero, stats, about preview, program preview, gallery preview, and CTA
- `about.html` — school history, vision/mission, values, and highlights
- `programs.html` — age-wise curriculum/program offerings
- `gallery.html` — photo gallery categories and media
- `contact.html` — contact information, embedded map, and Netlify-compatible enquiry form

## Styling Organization
- `css/style.css` — global styles (layout, nav, footer, shared components)
- `css/home.css` — home-page specific sections
- `css/about.css` — about-page styles
- `css/programs.css` — program-page styles
- `css/gallery.css` — gallery-page styles
- `css/contact.css` — contact-page styles

## JavaScript Organization
- `js/main.js`
  - injects reusable navbar and footer HTML into each page
  - highlights active page link based on `body[data-page]`
  - handles mobile hamburger menu
  - applies scroll-based reveal animations to `.fade-in` blocks
  - enables smooth scrolling for same-page anchor links
- `js/form.js`
  - validates required contact form fields
  - validates email and phone formats
  - shows inline field errors
  - on localhost only, intercepts submit and shows a success state for local testing

## How the site is wired
Each HTML file:
1. Includes the global stylesheet and its page-specific stylesheet.
2. Defines `<nav id="navbar"></nav>` and `<footer id="footer"></footer>` placeholders.
3. Loads `js/main.js` so navigation/footer rendering and interactions are shared.
4. `contact.html` additionally loads `js/form.js` for enquiry form behavior.

## Notes
- Form handling is set up for Netlify Forms in `contact.html` (`data-netlify="true"`, `form-name` hidden input, honeypot field).
- The gallery includes many static image assets grouped by event/theme folders.
- There is no build step or framework dependency; this can be served directly as static files.

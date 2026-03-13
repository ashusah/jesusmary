/* ═══════════════════════════════════════════════
   form.js — Contact form validation & handling
═══════════════════════════════════════════════ */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('queryForm');
  if (!form) return;

  form.addEventListener('submit', handleSubmit);

  // Live validation on blur
  form.querySelectorAll('input, select, textarea').forEach(field => {
    field.addEventListener('blur', () => validateField(field));
    field.addEventListener('input', () => clearError(field));
  });
});

/* ──────────────────────────────────────────────
   SUBMIT HANDLER
──────────────────────────────────────────────── */
function handleSubmit(e) {
  const form = e.target;
  const isValid = validateForm(form);

  if (!isValid) {
    e.preventDefault();
    return;
  }

  // For Netlify: let the form submit naturally
  // For testing locally: show success message
  if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
    e.preventDefault();
    showSuccess(form);
  }
  // On Netlify: form submits normally to Netlify Forms
}

/* ──────────────────────────────────────────────
   FORM VALIDATION
──────────────────────────────────────────────── */
function validateForm(form) {
  let isValid = true;
  const requiredFields = form.querySelectorAll('[required]');

  requiredFields.forEach(field => {
    if (!validateField(field)) isValid = false;
  });

  return isValid;
}

function validateField(field) {
  const value = field.value.trim();
  let error = '';

  if (field.hasAttribute('required') && !value) {
    error = 'This field is required.';
  } else if (field.type === 'email' && value && !isValidEmail(value)) {
    error = 'Please enter a valid email address.';
  } else if (field.type === 'tel' && value && !isValidPhone(value)) {
    error = 'Please enter a valid phone number.';
  }

  if (error) {
    showError(field, error);
    return false;
  } else {
    clearError(field);
    return true;
  }
}

/* ──────────────────────────────────────────────
   ERROR / SUCCESS UI
──────────────────────────────────────────────── */
function showError(field, message) {
  clearError(field);
  field.style.borderColor = '#C62828';

  const errEl = document.createElement('p');
  errEl.className = 'field-error';
  errEl.style.cssText = 'color:#C62828;font-size:0.78rem;margin-top:4px;font-weight:600;';
  errEl.textContent = message;

  field.parentNode.appendChild(errEl);
}

function clearError(field) {
  field.style.borderColor = '';
  const existing = field.parentNode.querySelector('.field-error');
  if (existing) existing.remove();
}

function showSuccess(form) {
  form.reset();
  form.style.display = 'none';

  const successEl = document.getElementById('formSuccess');
  if (successEl) {
    successEl.style.display = 'block';
  }
}

/* ──────────────────────────────────────────────
   HELPERS
──────────────────────────────────────────────── */
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
  return /^[\+]?[\d\s\-\(\)]{8,15}$/.test(phone);
}

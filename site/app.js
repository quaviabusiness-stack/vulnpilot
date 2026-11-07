// Vulnpilot landing page: copy button and waitlist form.
// The form posts straight to the Supabase REST API with the public anon key.
// That key can only INSERT the four columns below (see supabase/waitlist.sql);
// it cannot read, list, change or delete signups.

const SUPABASE_URL = 'https://xvdwfhadpmsgfpschnbp.supabase.co';
const SUPABASE_ANON_KEY =
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inh2ZHdmaGFkcG1zZ2Zwc2NobmJwIiwicm9sZSI6ImFub24iLCJpYXQiOjE3OTM5NzQwMTcsImV4cCI6MjEwOTU1MDAxN30.dj4dk1UgF0IlkYG7g3ovSAUhMpv1LuIv73P_UqGCrDQ';
const ENDPOINT = `${SUPABASE_URL}/rest/v1/vulnpilot_waitlist`;
const COMPANY_SIZES = ['1', '2-10', '11-50', '51-250', '250+'];
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const SOURCE_PATTERN = /^[a-z0-9._-]{1,32}$/;
const CONTACT = 'quavia.business@gmail.com';

function signupSource() {
  const raw = new URLSearchParams(window.location.search).get('utm_source');
  if (!raw) return 'direct';
  const source = raw.trim().toLowerCase();
  return SOURCE_PATTERN.test(source) ? source : 'other';
}

function setupCopyButtons() {
  for (const button of document.querySelectorAll('[data-copy]')) {
    const label = button.querySelector('.copy-label');
    let timer;
    button.addEventListener('click', async () => {
      let text = 'Copied';
      try {
        await navigator.clipboard.writeText(button.dataset.copy);
      } catch {
        text = 'Select';
      }
      label.textContent = text;
      clearTimeout(timer);
      timer = setTimeout(() => {
        label.textContent = 'Copy';
      }, 1800);
    });
  }
}

function setupWaitlistForm() {
  const form = document.getElementById('waitlist-form');
  if (!form) return;

  const email = form.elements.namedItem('email');
  const companySize = form.elements.namedItem('company_size');
  const consent = form.elements.namedItem('consent');
  const honeypot = form.elements.namedItem('website');
  const submit = form.querySelector('button[type="submit"]');
  const submitLabel = submit.querySelector('.btn-label');
  const status = document.getElementById('form-status');
  const success = document.getElementById('form-success');
  const emailError = document.getElementById('email-error');
  const consentError = document.getElementById('consent-error');

  function setFieldError(input, errorEl, message) {
    errorEl.textContent = message;
    errorEl.hidden = !message;
    if (message) input.setAttribute('aria-invalid', 'true');
    else input.removeAttribute('aria-invalid');
  }

  function setStatus(message, isError) {
    status.textContent = message;
    status.classList.toggle('is-error', Boolean(isError));
  }

  function showSuccess() {
    form.hidden = true;
    success.hidden = false;
    success.focus();
  }

  function setSending(sending) {
    submit.disabled = sending;
    submit.setAttribute('aria-busy', String(sending));
    submitLabel.textContent = sending ? 'Joining…' : 'Join the waitlist';
  }

  function validate() {
    const value = email.value.trim();
    let firstInvalid = null;
    if (!value) {
      setFieldError(email, emailError, 'Enter your email address.');
      firstInvalid = email;
    } else if (value.length > 254 || !EMAIL_PATTERN.test(value)) {
      setFieldError(email, emailError, 'Enter a valid email address.');
      firstInvalid = email;
    } else {
      setFieldError(email, emailError, '');
    }
    if (!consent.checked) {
      setFieldError(
        consent,
        consentError,
        'Please tick the box so we can email you.',
      );
      firstInvalid = firstInvalid || consent;
    } else {
      setFieldError(consent, consentError, '');
    }
    return firstInvalid;
  }

  email.addEventListener('blur', () => {
    if (email.getAttribute('aria-invalid') === 'true') validate();
  });
  consent.addEventListener('change', () => {
    if (consent.checked) setFieldError(consent, consentError, '');
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    if (submit.disabled) return;
    setStatus('', false);

    const firstInvalid = validate();
    if (firstInvalid) {
      firstInvalid.focus();
      return;
    }

    // Bots fill every field; people never see this one.
    if (honeypot.value) {
      showSuccess();
      return;
    }

    const size = companySize.value;
    const body = {
      email: email.value.trim(),
      consent: true,
      source: signupSource(),
      company_size: COMPANY_SIZES.includes(size) ? size : null,
    };

    setSending(true);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      const response = await fetch(ENDPOINT, {
        method: 'POST',
        headers: {
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
          'Content-Type': 'application/json',
          Prefer: 'return=minimal',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
      });
      // 409 means the address is already on the list. Treat it like a new
      // signup so the form never reveals whether an email is registered.
      if (response.status === 201 || response.status === 409) {
        showSuccess();
        return;
      }
      if (response.status === 400) {
        setFieldError(email, emailError, 'Enter a valid email address.');
        email.focus();
        return;
      }
      setStatus(
        `Something went wrong and you were not added. Please try again, or email ${CONTACT}.`,
        true,
      );
    } catch {
      setStatus(
        `We couldn't reach the server, so you were not added. Check your connection and try again, or email ${CONTACT}.`,
        true,
      );
    } finally {
      clearTimeout(timeout);
      setSending(false);
    }
  });
}

setupCopyButtons();
setupWaitlistForm();

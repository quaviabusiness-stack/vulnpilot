// Vulnpilot home page: copy buttons, the design partner (waitlist) form, the
// hero run, the hand-off of a dropped file to /scan, and small motion. Every
// part checks for its elements, and every animated state is also the final
// state in the HTML, so nothing depends on this script to be readable.
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

// A button copies either its data-copy text or the text of the element
// named in data-copy-from. The result is announced through #copy-status.
function setupCopyButtons() {
  const status = document.getElementById('copy-status');
  for (const button of document.querySelectorAll(
    '[data-copy], [data-copy-from]',
  )) {
    const label = button.querySelector('.copy-label');
    let timer;
    button.addEventListener('click', async () => {
      const source = button.dataset.copyFrom
        ? document.getElementById(button.dataset.copyFrom)
        : null;
      const value = source ? source.textContent : button.dataset.copy;
      let text = 'Copied';
      let announcement = 'Copied to the clipboard.';
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        text = 'Select';
        announcement = 'Copying failed. Select the text and copy it.';
      }
      label.textContent = text;
      if (status) status.textContent = announcement;
      clearTimeout(timer);
      timer = setTimeout(() => {
        label.textContent = 'Copy';
        if (status) status.textContent = '';
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
    submitLabel.textContent = sending ? 'Joining…' : 'Join as a design partner';
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

// ---------------------------------------------------------------------------
// Motion helpers. Everything below is skipped with prefers-reduced-motion.

const EASE_OUT = 'cubic-bezier(0.16, 1, 0.3, 1)';
const reducedMotion = () =>
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;
const easeOutExpo = (t) => (t >= 1 ? 1 : 1 - 2 ** (-10 * t));

/** Counts the last number in a text node up from zero, then restores the exact text. */
function countUp(node, duration, delay = 0) {
  const original = node.data;
  const match = /(\d+(?:\.\d+)?)(?!.*\d)/.exec(original);
  if (!match) return;
  const target = Number(match[1]);
  const decimals = match[1].includes('.') ? match[1].split('.')[1].length : 0;
  const before = original.slice(0, match.index);
  const after = original.slice(match.index + match[1].length);
  node.data = `${before}${(0).toFixed(decimals)}${after}`;
  setTimeout(() => {
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / duration);
      if (t >= 1) {
        node.data = original;
        return;
      }
      node.data = `${before}${(target * easeOutExpo(t)).toFixed(decimals)}${after}`;
      requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }, delay);
}

function firstNumberNode(element) {
  const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
  for (let node = walker.nextNode(); node; node = walker.nextNode())
    if (/\d/.test(node.data)) return node;
  return null;
}

// ---------------------------------------------------------------------------
// The hero run. The stylesheet prints the lines; this counts the summary up
// and shows the issues sorted by package before moving them to the order the
// CLI printed: known exploited first. The HTML order is never changed.

function setupHeroRun() {
  const figure = document.getElementById('hero-term');
  if (!figure || reducedMotion()) return;
  // The first counts print at about 540 ms. Starting later would make the
  // numbers or the issues jump while someone is already reading them.
  const now = performance.now();
  if (now > 500) return;
  const at = (ms) => Math.max(0, ms - now);

  for (const line of figure.querySelectorAll('.ln-count')) {
    const node = firstNumberNode(line);
    if (node) countUp(node, 760, at(540));
  }

  const issues = [...figure.querySelectorAll('.issue')].filter(
    (issue) => issue.offsetHeight > 0,
  );
  if (issues.length < 2) return;
  const tops = issues.map((issue) => issue.offsetTop);
  const found = [...issues].sort(
    (a, b) => Number(a.dataset.found) - Number(b.dataset.found),
  );
  const foundTop = new Map();
  let y = tops[0];
  for (const issue of found) {
    foundTop.set(issue, y);
    y += issue.offsetHeight;
  }
  const deltas = issues.map(
    (issue, index) => foundTop.get(issue) - tops[index],
  );
  if (deltas.every((delta) => delta === 0)) return;

  const state = figure.querySelector('.term-state');
  const stateText = figure.querySelector('.term-state-text');
  const ranked = stateText ? stateText.textContent : '';
  const setState = (text) => {
    if (!state || !stateText) return;
    state.classList.add('is-changing');
    setTimeout(() => {
      stateText.textContent = text;
      state.classList.remove('is-changing');
    }, 200);
  };

  figure.classList.add('is-sorting');
  if (stateText) stateText.textContent = 'Sorted by package';
  const rankAt = at(1700);
  issues.forEach((issue, index) => {
    if (deltas[index] === 0) return;
    issue.animate(
      [
        { transform: `translateY(${deltas[index]}px)` },
        { transform: 'translateY(0)' },
      ],
      {
        duration: 900,
        delay: rankAt,
        easing: EASE_OUT,
        fill: 'backwards',
      },
    );
  });
  setTimeout(() => {
    figure.classList.remove('is-sorting');
    setState(ranked);
  }, rankAt);
}

// ---------------------------------------------------------------------------
// A lockfile dropped on the home page opens in the browser scanner. The file
// goes into this browser's IndexedDB for /scan to pick up; it is not uploaded.

const HANDOFF_DB = 'vulnpilot-handoff';

function saveHandoff(file) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(HANDOFF_DB, 1);
    request.onupgradeneeded = () => request.result.createObjectStore('files');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const db = request.result;
      const transaction = db.transaction('files', 'readwrite');
      transaction.objectStore('files').put({ file, at: Date.now() }, 'dropped');
      transaction.oncomplete = () => {
        db.close();
        resolve();
      };
      transaction.onerror = () => {
        db.close();
        reject(transaction.error);
      };
    };
  });
}

function setupDropHandoff() {
  const figure = document.getElementById('hero-term');
  if (!figure || !('indexedDB' in window)) return;
  const hasFiles = (event) =>
    Boolean(event.dataTransfer) &&
    [...event.dataTransfer.types].includes('Files');
  let depth = 0;
  document.addEventListener('dragenter', (event) => {
    if (!hasFiles(event)) return;
    depth += 1;
    figure.classList.add('is-drop');
  });
  document.addEventListener('dragleave', (event) => {
    if (!hasFiles(event)) return;
    depth = Math.max(0, depth - 1);
    if (depth === 0) figure.classList.remove('is-drop');
  });
  document.addEventListener('dragover', (event) => {
    if (hasFiles(event)) event.preventDefault();
  });
  document.addEventListener('drop', async (event) => {
    if (!hasFiles(event)) return;
    event.preventDefault();
    depth = 0;
    figure.classList.remove('is-drop');
    const files = event.dataTransfer.files;
    if (files.length !== 1) {
      window.location.assign('/scan');
      return;
    }
    try {
      await saveHandoff(files[0]);
      window.location.assign('/scan?handoff');
    } catch {
      window.location.assign('/scan');
    }
  });
}

// ---------------------------------------------------------------------------
// Sections below the fold rise once as they arrive; the case figures count up.

function setupReveals() {
  if (reducedMotion() || !('IntersectionObserver' in window)) return;
  const targets = document.querySelectorAll(
    '.section-head, .problem-figure, .problem-body, .clock, .step, .cell, .figures, .compare-scroll, .plan, .partner-intro, .form-panel, .faq, .final-title, .final-actions',
  );
  const below = [...targets].filter(
    (element) => element.getBoundingClientRect().top > window.innerHeight,
  );
  const observer = new IntersectionObserver(
    (entries) => {
      for (const entry of entries) {
        if (!entry.isIntersecting) continue;
        entry.target.classList.add('is-in');
        observer.unobserve(entry.target);
      }
    },
    { rootMargin: '0px 0px -12% 0px' },
  );
  for (const element of below) {
    element.classList.add('reveal');
    observer.observe(element);
  }
}

function setupCounters() {
  const figures = document.querySelector('.figures');
  if (!figures || reducedMotion() || !('IntersectionObserver' in window))
    return;
  if (figures.getBoundingClientRect().top < window.innerHeight) return;
  const observer = new IntersectionObserver(
    (entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      observer.disconnect();
      figures.querySelectorAll('[data-proof]').forEach((element, index) => {
        const node = firstNumberNode(element);
        if (node) countUp(node, 1100, 120 + index * 70);
      });
    },
    { threshold: 0.4 },
  );
  observer.observe(figures);
}

// A soft light follows the pointer across the feature cells.
function setupSpotlight() {
  const bento = document.querySelector('.bento');
  if (
    !bento ||
    !window.matchMedia('(hover: hover) and (pointer: fine)').matches
  )
    return;
  let frame = 0;
  bento.addEventListener('pointermove', (event) => {
    const cell =
      event.target instanceof Element && event.target.closest('.cell');
    if (!cell || frame) return;
    frame = requestAnimationFrame(() => {
      frame = 0;
      const rect = cell.getBoundingClientRect();
      cell.style.setProperty('--mx', `${event.clientX - rect.left}px`);
      cell.style.setProperty('--my', `${event.clientY - rect.top}px`);
    });
  });
}

// On phones, a scan button stays at the bottom once the hero has gone, and
// steps aside for the form, the final call to action and the footer.
function setupStickyCta() {
  const bar = document.getElementById('sticky-cta');
  const hero = document.querySelector('.hero');
  if (!bar || !hero || !('IntersectionObserver' in window)) return;
  const quiet = [
    hero,
    document.getElementById('waitlist'),
    document.querySelector('.final'),
    document.querySelector('.site-footer'),
  ].filter(Boolean);
  const visible = new Set();
  bar.hidden = false;
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries)
      if (entry.isIntersecting) visible.add(entry.target);
      else visible.delete(entry.target);
    bar.classList.toggle('is-shown', visible.size === 0);
  });
  for (const element of quiet) observer.observe(element);
}

// The <details> menu closes when one of its links is followed.
function setupMenu() {
  const menu = document.querySelector('.menu');
  if (!menu) return;
  menu.addEventListener('click', (event) => {
    if (event.target instanceof Element && event.target.closest('a'))
      menu.open = false;
  });
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && menu.open) {
      menu.open = false;
      menu.querySelector('summary')?.focus();
    }
  });
}

document.documentElement.classList.add('js');
setupHeroRun();
setupCopyButtons();
setupWaitlistForm();
setupDropHandoff();
setupMenu();
setupReveals();
setupCounters();
setupSpotlight();
setupStickyCta();

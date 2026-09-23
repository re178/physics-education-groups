/* ============================================================
 * PHYSICS EDUCATION GROUPS — public/app.js
 * ------------------------------------------------------------
 * Version: 1.4.0
 *
 * Additions in this version:
 *   - Runtime CSS injection (payment + settings + notice classes)
 *   - Register page: payment-config check, dynamic field reveal
 *   - Admin page: settings form, payment column, SSE settings sync
 *   - Member modal: optional mpesaCode + paymentNote fields
 *   - Dashboard stat tiles: paid / unpaid counts
 *
 * All previously working features remain intact.
 * ============================================================ */
'use strict';

(function () {

  /* ============================================================
   * 0. Constants
   * ============================================================ */
  const DEVICE_KEY = 'peg_device_id_v1';
  const CSRF_COOKIE = 'peg_csrf';
  const CSRF_HEADER = 'X-CSRF-Token';

  /* ============================================================
   * 1. Runtime style injection
   * ------------------------------------------------------------
   * We add the few new classes used by the payment + settings UI
   * here, so that style.css does not need to be replaced.
   * ============================================================ */
  (function injectStyles() {
    if (document.getElementById('peg-app-styles')) return;
    const css = `
      .submission-status-row {
        display: flex;
        flex-wrap: wrap;
        gap: 14px 32px;
        align-items: center;
      }
      .submission-status-info {
        display: flex;
        flex-wrap: wrap;
        gap: 6px 10px;
        align-items: center;
      }
      .submission-status-label {
        font-weight: 600;
        color: #1f2937;
        font-size: 0.9rem;
      }
      .form-grid {
        display: grid;
        grid-template-columns: 1fr;
        gap: 16px;
      }
      @media (min-width: 640px) {
        .form-grid { grid-template-columns: 1fr 1fr; }
      }
      .span-full { grid-column: 1 / -1; }
      .field-checkbox {
        display: flex;
        flex-direction: column;
        gap: 4px;
      }
      .checkbox-label {
        display: flex;
        align-items: center;
        gap: 10px;
        cursor: pointer;
        font-weight: 600;
        font-size: 0.95rem;
      }
      .checkbox-label input[type="checkbox"] {
        width: 18px;
        height: 18px;
        min-height: 0;
        margin: 0;
        accent-color: #0b3d91;
        cursor: pointer;
      }
      .payment-body { display: flex; flex-direction: column; gap: 12px; }
      .payment-instructions p { margin: 0 0 8px; }
      .payment-phone-line { font-size: 1.05rem; }
      .payment-phone {
        font-weight: 700;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        letter-spacing: 0.02em;
        color: #0b3d91;
      }
      .payment-note-box {
        background: #fef9c3;
        border: 1px solid #fde68a;
        border-radius: 8px;
        padding: 12px 14px;
        margin: 12px 0;
      }
      .payment-note-title {
        font-weight: 700;
        color: #854d0e;
        margin: 0 0 6px;
      }
      .payment-note-list {
        margin: 0 0 8px 18px;
        padding: 0;
      }
      .payment-note-list li { margin-bottom: 2px; }
      .lab-manual-notice {
        background: #e7eefb;
        border: 1px solid #cfdcf4;
        border-left: 4px solid #0b3d91;
        border-radius: 8px;
        padding: 14px 16px;
        margin: 8px 0;
      }
      .lab-manual-title {
        margin: 0 0 6px;
        color: #0b3d91;
        font-size: 1.05rem;
      }
      .lab-manual-notice p {
        margin: 0 0 6px;
        font-size: 0.93rem;
      }
      .payment-cell { min-width: 100px; }
      .payment-cell .badge { font-size: 0.68rem; }
      .payment-cell .payment-mpesa-code {
        display: block;
        font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
        font-size: 0.7rem;
        color: #6b7280;
        margin-top: 2px;
        word-break: break-all;
      }
      .payment-cell .payment-note-line {
        display: block;
        font-size: 0.72rem;
        color: #6b7280;
        margin-top: 2px;
        white-space: normal;
        word-break: break-word;
      }
    `;
    const style = document.createElement('style');
    style.id = 'peg-app-styles';
    style.textContent = css;
    document.head.appendChild(style);
  })();

  /* ============================================================
   * 2. Small utilities
   * ============================================================ */
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const el = (tag, attrs = {}, children = []) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'class') node.className = v;
      else if (k === 'html') node.innerHTML = v;
      else if (k === 'text') node.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (v !== undefined && v !== null && v !== false) {
        node.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const child of [].concat(children)) {
      if (child == null) continue;
      node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
    }
    return node;
  };

  const getCookie = (name) => {
    const parts = document.cookie ? document.cookie.split('; ') : [];
    for (const part of parts) {
      const idx = part.indexOf('=');
      if (idx === -1) continue;
      if (part.slice(0, idx) === name) return decodeURIComponent(part.slice(idx + 1));
    }
    return null;
  };

  const formatDate = (iso) => {
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return '';
      return d.toLocaleString(undefined, {
        year: 'numeric', month: 'short', day: '2-digit',
        hour: '2-digit', minute: '2-digit',
      });
    } catch (_) { return ''; }
  };

  const formatDateShort = (iso) => {
    try {
      const d = new Date(iso);
      if (isNaN(d.getTime())) return '';
      return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' });
    } catch (_) { return ''; }
  };

  /* ============================================================
   * 3. Device fingerprint (persistent per browser)
   * ============================================================ */
  const Device = (function () {
    const uuid = () => {
      if (window.crypto && typeof window.crypto.randomUUID === 'function') {
        return window.crypto.randomUUID();
      }
      const b = new Uint8Array(16);
      (window.crypto || window.msCrypto).getRandomValues(b);
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      const h = Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
      return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    };

    const safeGet = (fn, fallback) => {
      try { return fn(); } catch (_) { return fallback; }
    };

    function loadOrCreateId() {
      try {
        let id = window.localStorage.getItem(DEVICE_KEY);
        if (!id || typeof id !== 'string' || id.length < 8) {
          id = uuid();
          window.localStorage.setItem(DEVICE_KEY, id);
        }
        return id;
      } catch (_) {
        if (!window.__peg_mem_device_id) window.__peg_mem_device_id = uuid();
        return window.__peg_mem_device_id;
      }
    }

    function collectMetadata() {
      const nav = window.navigator || {};
      const scr = window.screen || {};
      const dpr = window.devicePixelRatio || 1;

      return {
        userAgent: String(nav.userAgent || '').slice(0, 500),
        platform: String(nav.platform || '').slice(0, 120),
        language: String(nav.language || '').slice(0, 60),
        languages: Array.isArray(nav.languages) ? nav.languages.slice(0, 10) : [],
        timezone: safeGet(
          () => String(Intl.DateTimeFormat().resolvedOptions().timeZone || ''),
          ''
        ).slice(0, 80),
        screen: {
          width: Number(scr.width) || 0,
          height: Number(scr.height) || 0,
          colorDepth: Number(scr.colorDepth) || 0,
          pixelRatio: Number(dpr) || 0,
        },
        viewport: {
          width: Number(window.innerWidth) || 0,
          height: Number(window.innerHeight) || 0,
        },
        hardwareConcurrency: Number(nav.hardwareConcurrency) || 0,
        deviceMemory: Number(nav.deviceMemory) || 0,
        touchSupport: Boolean(
          'ontouchstart' in window ||
          (nav.maxTouchPoints && nav.maxTouchPoints > 0)
        ),
        online: nav.onLine !== false,
        cookieEnabled: nav.cookieEnabled !== false,
        doNotTrack: String(
          nav.doNotTrack || window.doNotTrack || nav.msDoNotTrack || ''
        ).slice(0, 20),
      };
    }

    return {
      getId: loadOrCreateId,
      getMetadata: collectMetadata,
    };
  })();

  /* ============================================================
   * 4. Alerts
   * ============================================================ */
  const Alert = (function () {
    const ICONS = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ',
    };

    function render(type, message, opts = {}) {
      const region = document.getElementById('alert-region');
      if (!region) return null;

      const { title = null, dismissible = true, timeout = 0 } = opts;

      const node = el('div', { class: `alert alert-${type}`, role: 'alert' }, [
        el('span', { class: 'alert-icon', 'aria-hidden': 'true', text: ICONS[type] || '•' }),
        el('div', { class: 'alert-body' }, [
          title ? el('p', { class: 'alert-title', text: title }) : null,
          el('p', { class: 'alert-message', text: message }),
        ]),
      ]);

      if (dismissible) {
        const close = el('button', {
          type: 'button',
          class: 'alert-dismiss',
          'aria-label': 'Dismiss',
          onClick: () => node.remove(),
        }, ['×']);
        node.appendChild(close);
      }

      region.appendChild(node);

      if (timeout > 0) {
        setTimeout(() => {
          if (node.parentNode) node.remove();
        }, timeout);
      }

      try { node.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (_) {}

      return node;
    }

    function clear() {
      const region = document.getElementById('alert-region');
      if (region) region.innerHTML = '';
    }

    function isShowing() {
      const region = document.getElementById('alert-region');
      return region ? region.children.length > 0 : false;
    }

    return {
      success: (m, o) => render('success', m, o),
      error: (m, o) => render('error', m, o),
      warning: (m, o) => render('warning', m, o),
      info: (m, o) => render('info', m, o),
      clear,
      isShowing,
    };
  })();

  /* ============================================================
   * 5. Modal helpers
   * ============================================================ */
  const Modal = (function () {
    function open(id) {
      const node = document.getElementById(id);
      if (!node) return;
      node.hidden = false;
      document.body.style.overflow = 'hidden';
      const focusable = node.querySelector('input, select, textarea, button');
      if (focusable) setTimeout(() => { try { focusable.focus(); } catch (_) {} }, 30);
    }

    function close(id) {
      const node = document.getElementById(id);
      if (!node) return;
      node.hidden = true;
      const anyOpen = $$('.modal-backdrop').some((m) => !m.hidden);
      if (!anyOpen) document.body.style.overflow = '';
    }

    function closeAll() {
      $$('.modal-backdrop').forEach((m) => { m.hidden = true; });
      document.body.style.overflow = '';
    }

    document.addEventListener('click', (e) => {
      const closeBtn = e.target.closest('[data-close-modal]');
      if (closeBtn) {
        const backdrop = closeBtn.closest('.modal-backdrop');
        if (backdrop) close(backdrop.id);
      }
      if (e.target.classList && e.target.classList.contains('modal-backdrop')) {
        close(e.target.id);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeAll();
    });

    let pendingConfirmResolve = null;
    function confirm(message, opts = {}) {
      const { title = 'Confirm', okText = 'Confirm', cancelText = 'Cancel' } = opts;
      const modal = document.getElementById('modal-confirm');
      if (!modal) return Promise.resolve(window.confirm(message));

      $('#confirm-title', modal).textContent = title;
      $('#confirm-message', modal).textContent = message;
      const okBtn = $('#confirm-ok', modal);
      const cancelBtn = $('#confirm-cancel', modal);
      okBtn.textContent = okText;
      cancelBtn.textContent = cancelText;

      const newOk = okBtn.cloneNode(true);
      const newCancel = cancelBtn.cloneNode(true);
      okBtn.parentNode.replaceChild(newOk, okBtn);
      cancelBtn.parentNode.replaceChild(newCancel, cancelBtn);

      open('modal-confirm');

      return new Promise((resolve) => {
        pendingConfirmResolve = resolve;
        newOk.addEventListener('click', () => {
          close('modal-confirm');
          if (pendingConfirmResolve) { pendingConfirmResolve(true); pendingConfirmResolve = null; }
        });
        newCancel.addEventListener('click', () => {
          close('modal-confirm');
          if (pendingConfirmResolve) { pendingConfirmResolve(false); pendingConfirmResolve = null; }
        });
      });
    }

    return { open, close, closeAll, confirm };
  })();

  /* ============================================================
   * 6. API helper (with CSRF)
   * ============================================================ */
  let csrfTokenCache = null;
  let csrfFetchPromise = null;

  async function getCsrfToken(force = false) {
    if (!force && csrfTokenCache) return csrfTokenCache;
    if (csrfFetchPromise) return csrfFetchPromise;

    csrfFetchPromise = (async () => {
      try {
        const res = await fetch('/api/csrf-token', {
          method: 'GET',
          credentials: 'same-origin',
          headers: { Accept: 'application/json' },
        });
        const data = await res.json().catch(() => ({}));
        const token = data && data.token ? data.token : getCookie(CSRF_COOKIE);
        if (token) csrfTokenCache = token;
        return csrfTokenCache;
      } catch (_) {
        return getCookie(CSRF_COOKIE);
      } finally {
        csrfFetchPromise = null;
      }
    })();

    return csrfFetchPromise;
  }

  async function api(path, options = {}) {
    const method = (options.method || 'GET').toUpperCase();
    const isMutating = !['GET', 'HEAD', 'OPTIONS'].includes(method);

    const headers = Object.assign(
      { Accept: 'application/json' },
      options.headers || {}
    );

    let body = options.body;
    if (body !== undefined && body !== null && !(body instanceof FormData) && typeof body !== 'string') {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }

    if (isMutating) {
      const token = await getCsrfToken();
      if (token) headers[CSRF_HEADER] = token;
    }

    let res;
    try {
      res = await fetch(path, {
        method,
        headers,
        body,
        credentials: 'same-origin',
        cache: 'no-store',
      });
    } catch (networkErr) {
      return {
        ok: false,
        status: 0,
        data: {
          success: false,
          message: 'Network error. Please check your connection and try again.',
          code: 'NETWORK_ERROR',
        },
      };
    }

    let data = null;
    const ct = res.headers.get('content-type') || '';
    if (ct.includes('application/json')) {
      data = await res.json().catch(() => null);
    } else {
      const text = await res.text().catch(() => '');
      data = text ? { success: res.ok, message: text } : null;
    }

    if (res.status === 403 && data && data.code === 'CSRF_INVALID') {
      await getCsrfToken(true);
      const token = csrfTokenCache;
      if (token) headers[CSRF_HEADER] = token;
      try {
        const retry = await fetch(path, {
          method, headers, body, credentials: 'same-origin', cache: 'no-store',
        });
        const retryData = await retry.json().catch(() => null);
        return { ok: retry.ok, status: retry.status, data: retryData };
      } catch (_) { /* fall through */ }
    }

    return { ok: res.ok, status: res.status, data };
  }

  /* ============================================================
   * 7. Button loading helper
   * ============================================================ */
  function withLoading(btn, asyncFn) {
    return async (...args) => {
      if (!btn) return asyncFn(...args);
      if (btn.classList.contains('is-loading')) return;
      btn.classList.add('is-loading');
      btn.disabled = true;
      try {
        return await asyncFn(...args);
      } finally {
        btn.classList.remove('is-loading');
        btn.disabled = false;
      }
    };
  }

  /* ============================================================
   * 8. Field-level error display
   * ============================================================ */
  function setFieldError(fieldName, message) {
    const errNode = document.querySelector(`[data-error-for="${fieldName}"]`);
    const input = document.getElementById(fieldName);
    if (errNode) {
      if (message) {
        errNode.textContent = message;
        errNode.hidden = false;
      } else {
        errNode.textContent = '';
        errNode.hidden = true;
      }
    }
    if (input) {
      if (message) input.setAttribute('aria-invalid', 'true');
      else input.removeAttribute('aria-invalid');
    }
  }

  function clearFieldErrors(form) {
    if (!form) return;
    $$('.field-error', form).forEach((n) => { n.hidden = true; n.textContent = ''; });
    $$('[aria-invalid]', form).forEach((n) => n.removeAttribute('aria-invalid'));
  }

  /* ============================================================
   * 9. Show / hide password toggles
   * ============================================================ */
  function wireVisibilityToggles() {
    $$('[data-toggle-for]').forEach((btn) => {
      btn.addEventListener('click', () => {
        const targetId = btn.getAttribute('data-toggle-for');
        const input = document.getElementById(targetId);
        if (!input) return;
        const show = input.type === 'password';
        input.type = show ? 'text' : 'password';
        btn.textContent = show ? 'Hide' : 'Show';
        btn.setAttribute('aria-pressed', String(show));
      });
    });
  }

  /* ============================================================
   * 10. Payment cell renderer (used by admin tables)
   * ============================================================ */
  function buildPaymentCell(member) {
    const td = el('td', { class: 'payment-cell' });
    const code = member && member.mpesaCode ? String(member.mpesaCode) : '';

    if (code) {
      td.appendChild(el('span', { class: 'badge badge-open', text: 'PAID' }));
      td.appendChild(el('span', { class: 'payment-mpesa-code', text: code }));
      if (member.paymentNote) {
        td.appendChild(el('span', { class: 'payment-note-line', text: member.paymentNote }));
      }
    } else {
      td.appendChild(el('span', { class: 'badge badge-member', text: 'UNPAID' }));
    }
    return td;
  }

  /* ============================================================
   * 11. REGISTRATION PAGE (index.html)
   * ============================================================ */
  function initRegisterPage() {
    const form = document.getElementById('register-form');
    if (!form) return;

    const deviceIdInput = document.getElementById('deviceId');
    const deviceMetaInput = document.getElementById('deviceMetadata');
    if (deviceIdInput) deviceIdInput.value = Device.getId();
    if (deviceMetaInput) deviceMetaInput.value = JSON.stringify(Device.getMetadata());

    const submitBtn = document.getElementById('submit-btn');
    const successCard = document.getElementById('success-card');

    // Payment UI nodes
    const paymentCard = document.getElementById('payment-card');
    const paymentAmountSpan = document.getElementById('payment-amount');
    const paymentPhoneSpan = document.getElementById('payment-phone');
    const fieldMpesa = document.getElementById('field-mpesa');
    const fieldPaymentNote = document.getElementById('field-payment-note');
    const heroCapacity = document.getElementById('hero-capacity');

    // Runtime state
    const state = {
      registrationOpen: true,
      requirePaymentProof: false,
      paymentAmount: 45,
      paymentPhone: '0741742291',
      maxGroupMembers: 10,
    };

    function applyConfig(cfg) {
      if (!cfg || typeof cfg !== 'object') return;

      if (typeof cfg.registrationOpen === 'boolean') state.registrationOpen = cfg.registrationOpen;
      if (typeof cfg.requirePaymentProof === 'boolean') state.requirePaymentProof = cfg.requirePaymentProof;
      if (cfg.paymentAmount != null) state.paymentAmount = Number(cfg.paymentAmount) || state.paymentAmount;
      if (cfg.paymentPhone) state.paymentPhone = String(cfg.paymentPhone);
      if (cfg.maxGroupMembers != null) state.maxGroupMembers = Number(cfg.maxGroupMembers) || state.maxGroupMembers;

      // Capacity hint in hero
      if (heroCapacity) heroCapacity.textContent = `${state.maxGroupMembers} members`;

      // Payment card + fields
      if (paymentCard) {
        paymentCard.hidden = !state.requirePaymentProof;
      }
      if (fieldMpesa) {
        fieldMpesa.hidden = !state.requirePaymentProof;
      }
      if (fieldPaymentNote) {
        fieldPaymentNote.hidden = !state.requirePaymentProof;
      }

      // Displayed amount + phone
      if (paymentAmountSpan) paymentAmountSpan.textContent = String(state.paymentAmount);
      if (paymentPhoneSpan) paymentPhoneSpan.textContent = state.paymentPhone;

      // Registration-open notice handling
      const existingNotice = document.getElementById('registration-closed-notice');
      const formWrap = form.closest('.card');

      if (!state.registrationOpen) {
        if (!existingNotice && formWrap && formWrap.parentNode) {
          const notice = el('div', { class: 'card card-info', id: 'registration-closed-notice' }, [
            el('div', { class: 'card-head' }, [
              el('h2', { text: 'Registration is currently closed' }),
            ]),
            el('p', {
              text:
                'Student registration submissions are temporarily closed. ' +
                'Please check back later or contact the Administrator.',
            }),
          ]);
          formWrap.parentNode.insertBefore(notice, formWrap);
        }
        form.hidden = true;
        if (submitBtn) submitBtn.disabled = true;
      } else {
        if (existingNotice) existingNotice.remove();
        form.hidden = false;
        if (submitBtn) submitBtn.disabled = false;
      }
    }

    // Fetch config on load
    (async () => {
      try {
        const { ok, data } = await api('/api/payment-config');
        if (ok && data && data.success) {
          applyConfig(data);
        } else {
          // Fall back to status-only check
          const statusRes = await api('/api/registration-status');
          if (statusRes.ok && statusRes.data && typeof statusRes.data.open === 'boolean') {
            applyConfig({ registrationOpen: statusRes.data.open });
          }
        }
      } catch (_) {
        applyConfig({ registrationOpen: true });
      }
    })();

    form.addEventListener('reset', () => {
      clearFieldErrors(form);
      Alert.clear();
      if (successCard) successCard.hidden = true;
    });

    form.addEventListener('submit', withLoading(submitBtn, async (e) => {
      e.preventDefault();
      clearFieldErrors(form);
      Alert.clear();

      if (!state.registrationOpen) {
        Alert.warning(
          'Registration is currently closed. Please check back later.',
          { title: 'Registration closed' }
        );
        return;
      }

      const regNo = ($('#regNo') || {}).value || '';
      const name = ($('#name') || {}).value || '';
      const phone = ($('#phone') || {}).value || '';
      const groupName = ($('#groupName') || {}).value || '';
      const mpesaCode = state.requirePaymentProof ? (($('#mpesaCode') || {}).value || '') : '';
      const paymentNote = state.requirePaymentProof ? (($('#paymentNote') || {}).value || '') : '';

      let hasError = false;
      if (!regNo.trim()) { setFieldError('regNo', 'Registration number is required.'); hasError = true; }
      else if (regNo.trim().length < 3) { setFieldError('regNo', 'Registration number is too short.'); hasError = true; }

      if (!name.trim()) { setFieldError('name', 'Full name is required.'); hasError = true; }
      else if (name.trim().length < 2) { setFieldError('name', 'Full name is too short.'); hasError = true; }

      if (!phone.trim()) { setFieldError('phone', 'Phone number is required.'); hasError = true; }

      if (!groupName.trim()) { setFieldError('groupName', 'Group name is required.'); hasError = true; }

      if (state.requirePaymentProof) {
        const code = mpesaCode.trim().toUpperCase();
        if (!code) {
          setFieldError('mpesaCode', 'M-Pesa confirmation code is required.');
          hasError = true;
        } else if (!/^[A-Z0-9]{10}$/.test(code)) {
          setFieldError('mpesaCode', 'Enter the 10-character code from the M-Pesa SMS.');
          hasError = true;
        }
        if (!paymentNote.trim()) {
          setFieldError('paymentNote', 'Please note the time and day you paid.');
          hasError = true;
        }
      }

      if (hasError) {
        Alert.warning('Please complete all required fields correctly.', { title: 'Check your input' });
        return;
      }

      const payload = {
        regNo: regNo.trim(),
        name: name.trim(),
        phone: phone.trim(),
        groupName: groupName.trim(),
        deviceId: Device.getId(),
        deviceMetadata: Device.getMetadata(),
      };
      if (state.requirePaymentProof) {
        payload.mpesaCode = mpesaCode.trim().toUpperCase();
        payload.paymentNote = paymentNote.trim();
      }

      const { ok, data } = await api('/api/register', {
        method: 'POST',
        body: payload,
      });

      if (ok && data && data.success) {
        showSuccess(data);
        Alert.clear();
        return;
      }

      const message = (data && data.message) || 'We could not complete your registration. Please contact the Administrator.';
      const code = (data && data.code) || 'SERVER_ERROR';

      if (code === 'INVALID_REQNO') setFieldError('regNo', message);
      else if (code === 'INVALID_NAME') setFieldError('name', message);
      else if (code === 'INVALID_PHONE') setFieldError('phone', message);
      else if (code === 'INVALID_GROUP') setFieldError('groupName', message);
      else if (code === 'DUPLICATE_REGNO') setFieldError('regNo', 'This registration number is already registered.');
      else if (code === 'PAYMENT_REQUIRED') setFieldError('mpesaCode', message);
      else if (code === 'PAYMENT_NOTE_REQUIRED') setFieldError('paymentNote', message);

      if (code === 'DUPLICATE_REGNO') {
        Alert.warning(message, { title: 'Duplicate registration' });
      } else if (code === 'GROUP_FULL') {
        Alert.warning(message, { title: 'Group full' });
      } else if (code === 'DEVICE_USED') {
        Alert.warning(message, { title: 'Device already used' });
      } else if (code === 'REGISTRATION_CLOSED') {
        state.registrationOpen = false;
        applyConfig({ registrationOpen: false });
        Alert.warning(message, { title: 'Registration closed' });
      } else if (
        code === 'INVALID_REQNO' ||
        code === 'INVALID_NAME' ||
        code === 'INVALID_PHONE' ||
        code === 'INVALID_GROUP' ||
        code === 'PAYMENT_REQUIRED' ||
        code === 'PAYMENT_NOTE_REQUIRED'
      ) {
        Alert.error(message, { title: 'Check your input' });
      } else if (!Alert.isShowing()) {
        Alert.error(message, { title: 'Registration failed' });
      }
    }));

    function showSuccess(data) {
      if (!successCard) return;
      form.hidden = true;

      const msgEl = document.getElementById('success-message');
      const details = document.getElementById('success-details');
      const loginLink = document.getElementById('success-login-link');
      const anotherBtn = document.getElementById('success-register-another');

      if (msgEl) msgEl.textContent = data.message || 'Registration successful.';
      if (details) {
        details.innerHTML = '';
        const g = data.group || {};
        const m = data.member || {};
        const rows = [
          ['Registration No', m.regNo || ''],
          ['Full Name', m.name || ''],
          ['Phone Number', m.phone || ''],
          ['Group', g.name || ''],
          ['Role', m.isLeader ? 'GROUP LEADER' : 'MEMBER'],
          ['Members in Group', `${g.memberCount || 0} / ${g.capacity || state.maxGroupMembers}`],
        ];

        // Show payment info if it was captured
        if (m.mpesaCode) {
          rows.push(['M-Pesa Code', m.mpesaCode]);
          if (m.paymentAmount != null) rows.push(['Amount Paid (KSH)', String(m.paymentAmount)]);
          if (m.paymentNote) rows.push(['Time & Day Paid', m.paymentNote]);
        }

        for (const [k, v] of rows) {
          details.appendChild(el('dt', { text: k }));
          details.appendChild(el('dd', { text: String(v) }));
        }
      }
      if (loginLink && data.group && data.group.name) {
        loginLink.href = '/member-login';
      }
      if (anotherBtn) {
        anotherBtn.addEventListener('click', () => {
          Alert.info(
            'To register another student, please use a different device or browser.',
            { title: 'One device per registration' }
          );
        });
      }

      successCard.hidden = false;
      try { successCard.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_) {}
    }
  }

  /* ============================================================
   * 12. MEMBER PAGE (member.html)
   * ============================================================ */
  async function initMemberPage() {
    const loginView = document.getElementById('view-login');
    const dashView = document.getElementById('view-dashboard');
    const loginForm = document.getElementById('member-login-form');
    const loginBtn = document.getElementById('member-login-btn');
    const logoutBtn = document.getElementById('member-logout-btn');
    const dashLogoutBtn = document.getElementById('dash-logout-btn');
    const refreshBtn = document.getElementById('dash-refresh-btn');

    if (!loginView || !dashView) return;

    const showLogin = () => {
      loginView.hidden = false;
      dashView.hidden = true;
      if (logoutBtn) logoutBtn.hidden = true;
    };

    const showDashboard = () => {
      loginView.hidden = true;
      dashView.hidden = false;
      if (logoutBtn) logoutBtn.hidden = false;
    };

    const me = await api('/api/member/me');
    if (me.ok && me.data && me.data.success && me.data.member) {
      await loadMemberGroup();
      showDashboard();
    } else {
      showLogin();
    }

    if (loginForm) {
      loginForm.addEventListener('submit', withLoading(loginBtn, async (e) => {
        e.preventDefault();
        clearFieldErrors(loginForm);
        Alert.clear();

        const groupName = ($('#loginGroupName') || {}).value || '';
        const regNo = ($('#loginRegNo') || {}).value || '';

        let hasError = false;
        if (!groupName.trim()) { setFieldError('loginGroupName', 'Group name is required.'); hasError = true; }
        if (!regNo.trim()) { setFieldError('loginRegNo', 'Registration number is required.'); hasError = true; }
        if (hasError) {
          Alert.warning('Please enter both your Group Name and Registration Number.');
          return;
        }

        const { ok, data } = await api('/api/member/login', {
          method: 'POST',
          body: { groupName: groupName.trim(), regNo: regNo.trim() },
        });

        if (ok && data && data.success) {
          Alert.success('Login successful.', { timeout: 2500 });
          loginForm.reset();
          await loadMemberGroup();
          showDashboard();
        } else {
          Alert.error(
            (data && data.message) || 'Login failed. Check your group name and registration number.',
            { title: 'Login failed' }
          );
        }
      }));
    }

    async function doLogout() {
      const { ok } = await api('/api/member/logout', { method: 'POST' });
      if (ok) {
        Alert.info('You have been logged out.', { timeout: 2500 });
        showLogin();
        const tbody = document.getElementById('member-table-body');
        if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="table-empty">Loading…</td></tr>';
      } else {
        Alert.error('Could not log out. Please try again.');
      }
    }

    if (logoutBtn) logoutBtn.addEventListener('click', doLogout);
    if (dashLogoutBtn) dashLogoutBtn.addEventListener('click', doLogout);

    if (refreshBtn) {
      refreshBtn.addEventListener('click', withLoading(refreshBtn, async () => {
        await loadMemberGroup();
        Alert.success('Refreshed.', { timeout: 1500 });
      }));
    }

    async function loadMemberGroup() {
      const { ok, data } = await api('/api/member/group');
      if (!ok || !data || !data.success) {
        if (data && data.code === 'AUTH_REQUIRED') {
          showLogin();
          return;
        }
        Alert.error((data && data.message) || 'Could not load your group.');
        return;
      }

      const group = data.group || {};
      const members = data.members || [];
      const viewer = data.viewer || {};

      const nameEl = document.getElementById('dash-member-name');
      if (nameEl) nameEl.textContent = viewer.name || 'Member';

      const gNameEl = document.getElementById('dash-group-name');
      if (gNameEl) gNameEl.textContent = group.name || '—';

      const leaderName = document.getElementById('dash-leader-name');
      const leaderReg = document.getElementById('dash-leader-regno');
      if (leaderName) leaderName.textContent = group.leaderName || '—';
      if (leaderReg) leaderReg.textContent = group.leaderRegNo ? `REG: ${group.leaderRegNo}` : '';

      const countEl = document.getElementById('dash-member-count');
      const capEl = document.getElementById('dash-capacity');
      const capacity = group.capacity || 10;
      const memberCount = group.memberCount || members.length;
      if (countEl) countEl.textContent = String(memberCount);
      if (capEl) capEl.textContent = String(capacity);

      const roleEl = document.getElementById('dash-your-role');
      if (roleEl) roleEl.textContent = viewer.isLeader ? 'GROUP LEADER' : 'MEMBER';

      const fill = document.getElementById('dash-capacity-fill');
      const text = document.getElementById('dash-capacity-text');
      const pct = capacity > 0 ? Math.min(100, Math.round((memberCount / capacity) * 100)) : 0;
      if (fill) {
        fill.style.width = pct + '%';
        fill.classList.toggle('is-full', pct >= 100);
      }
      if (text) text.textContent = `${memberCount} / ${capacity} members`;

      const tbody = document.getElementById('member-table-body');
      if (!tbody) return;
      tbody.innerHTML = '';

      if (members.length === 0) {
        tbody.appendChild(el('tr', {}, [
          el('td', { colspan: '5', class: 'table-empty', text: 'No members.' }),
        ]));
        return;
      }

      members.forEach((m, i) => {
        const tr = el('tr', { class: m.isLeader ? 'is-leader' : '' });
        tr.appendChild(el('td', { text: String(i + 1) }));
        tr.appendChild(el('td', { class: 'mono', text: m.regNo || '' }));
        tr.appendChild(el('td', { text: m.name || '' }));
        tr.appendChild(el('td', { text: m.phone || '' }));
        tr.appendChild(el('td', {}, [
          el('span', {
            class: 'badge ' + (m.isLeader ? 'badge-leader' : 'badge-member'),
            text: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
          }),
        ]));
        tbody.appendChild(tr);
      });
    }
  }

  /* ============================================================
   * 13. ADMIN PAGE (admin.html)
   * ============================================================ */
  async function initAdminPage() {
    const loginView = document.getElementById('view-login');
    const dashView = document.getElementById('view-dashboard');
    const groupView = document.getElementById('view-group');
    if (!loginView || !dashView || !groupView) return;

    const loginForm = document.getElementById('admin-login-form');
    const loginBtn = document.getElementById('admin-login-btn');
    const logoutBtn = document.getElementById('admin-logout-btn');
    const liveIndicator = document.getElementById('live-indicator');

    /* ---- STATE ---- */
    let sse = null;
    let sseReconnectDelay = 1000;
    let currentGroupId = null;
    let currentGroupData = null;

    /* ---- Registration + payment status pills ---- */
    function renderRegistrationStatus(open) {
      const pill = document.getElementById('submissions-status-pill');
      const help = document.getElementById('submissions-status-help');
      const toggleBtn = document.getElementById('btn-toggle-registration');

      if (pill) {
        pill.textContent = open ? 'OPEN' : 'CLOSED';
        pill.classList.toggle('badge-open', open);
        pill.classList.toggle('badge-full', !open);
      }
      if (help) {
        help.textContent = open
          ? 'New students can currently register themselves.'
          : 'New student registrations are currently blocked.';
      }
      if (toggleBtn) {
        const label = toggleBtn.querySelector('.btn-label');
        if (label) {
          label.textContent = open ? 'Close Submissions' : 'Open Submissions';
        }
        toggleBtn.classList.toggle('btn-danger-outline', open);
        toggleBtn.classList.toggle('btn-primary', !open);
      }
    }

    function renderPaymentStatus(requirePaymentProof) {
      const pill = document.getElementById('payment-status-pill');
      const help = document.getElementById('payment-status-help');

      if (pill) {
        pill.textContent = requirePaymentProof ? 'ON' : 'OFF';
        pill.classList.toggle('badge-full', requirePaymentProof);
        pill.classList.toggle('badge-member', !requirePaymentProof);
        pill.classList.toggle('badge-open', false);
      }
      if (help) {
        help.textContent = requirePaymentProof
          ? 'Students must submit an M-Pesa code (KSH 45 → Pochi).'
          : 'M-Pesa code is not required on registration.';
      }
    }

    /* ---- Settings form ---- */
    const settingsForm = document.getElementById('settings-form');
    const settingsSaveBtn = document.getElementById('settings-save-btn');
    const settingsResetBtn = document.getElementById('settings-reset-btn');
    const settingsSavedAt = document.getElementById('settings-saved-at');

    let currentSettings = null;

    function fillSettingsForm(s) {
      if (!s) return;
      currentSettings = s;
      const requireChk = document.getElementById('setting-require-payment');
      const amountInp = document.getElementById('setting-payment-amount');
      const phoneInp = document.getElementById('setting-payment-phone');
      const maxInp = document.getElementById('setting-max-members');
      const maxHelp = document.getElementById('setting-max-help');

      if (requireChk) requireChk.checked = s.requirePaymentProof === true;
      if (amountInp) amountInp.value = s.paymentAmount != null ? String(s.paymentAmount) : '45';
      if (phoneInp) phoneInp.value = s.paymentPhone || '0741742291';
      if (maxInp) {
        maxInp.value = s.maxGroupMembers != null ? String(s.maxGroupMembers) : '10';
        maxInp.max = String(s.maxGroupMembersHardLimit || 20);
      }
      if (maxHelp && s.maxGroupMembersHardLimit) {
        maxHelp.textContent =
          `Between 1 and ${s.maxGroupMembersHardLimit}. Applies to new registrations only — existing groups keep their members.`;
      }

      renderRegistrationStatus(s.registrationOpen !== false);
      renderPaymentStatus(s.requirePaymentProof === true);

      if (settingsSavedAt) {
        settingsSavedAt.textContent = 'Loaded from server at ' + new Date().toLocaleTimeString();
      }
    }

    async function loadSettings() {
      const { ok, data } = await api('/api/admin/settings');
      if (ok && data && data.success) {
        fillSettingsForm(data);
      }
    }

    if (settingsForm) {
      settingsForm.addEventListener('submit', withLoading(settingsSaveBtn, async (e) => {
        e.preventDefault();
        clearFieldErrors(settingsForm);

        const requireChk = document.getElementById('setting-require-payment');
        const amountInp = document.getElementById('setting-payment-amount');
        const phoneInp = document.getElementById('setting-payment-phone');
        const maxInp = document.getElementById('setting-max-members');

        const payload = {
          requirePaymentProof: Boolean(requireChk && requireChk.checked),
          paymentAmount: Number(amountInp ? amountInp.value : 45),
          paymentPhone: phoneInp ? phoneInp.value.trim() : '',
          maxGroupMembers: Number(maxInp ? maxInp.value : 10),
        };

        let hasError = false;
        if (!Number.isFinite(payload.paymentAmount) || payload.paymentAmount < 0) {
          setFieldError('setting-payment-amount', 'Enter a valid amount (≥ 0).');
          hasError = true;
        }
        if (!payload.paymentPhone) {
          setFieldError('setting-payment-phone', 'Payment phone is required.');
          hasError = true;
        }
        if (!Number.isFinite(payload.maxGroupMembers) || payload.maxGroupMembers < 1 || payload.maxGroupMembers > 20) {
          setFieldError('setting-max-members', 'Must be between 1 and 20.');
          hasError = true;
        }
        if (hasError) {
          Alert.error('Please fix the highlighted fields.', { title: 'Invalid settings' });
          return;
        }

        const { ok, data } = await api('/api/admin/settings', {
          method: 'POST',
          body: payload,
        });

        if (ok && data && data.success) {
          Alert.success(data.message || 'Settings saved.', { timeout: 2500 });
          fillSettingsForm({
            registrationOpen: data.registrationOpen,
            requirePaymentProof: data.requirePaymentProof,
            paymentAmount: data.paymentAmount,
            paymentPhone: data.paymentPhone,
            maxGroupMembers: data.maxGroupMembers,
            maxGroupMembersHardLimit: data.maxGroupMembersHardLimit,
          });
          if (settingsSavedAt) {
            settingsSavedAt.textContent = 'Last saved at ' + new Date().toLocaleTimeString();
          }
          // Refresh the dashboard so tiles reflect the new cap
          loadDashboard();
        } else {
          Alert.error((data && data.message) || 'Could not save settings.');
        }
      }));
    }

    if (settingsResetBtn) {
      settingsResetBtn.addEventListener('click', () => {
        if (currentSettings) {
          fillSettingsForm(currentSettings);
          Alert.info('Form reset to the last saved values.', { timeout: 1800 });
        } else {
          loadSettings();
        }
      });
    }

    /* ---- SSE ---- */
    function startSse() {
      if (sse) return;
      try {
        sse = new EventSource('/api/admin/events', { withCredentials: true });

        sse.addEventListener('open', () => {
          sseReconnectDelay = 1000;
          if (liveIndicator) liveIndicator.hidden = false;
        });

        sse.addEventListener('error', () => {
          if (liveIndicator) liveIndicator.hidden = true;
          if (sse && sse.readyState === EventSource.CLOSED) {
            stopSse();
            setTimeout(startSse, sseReconnectDelay);
            sseReconnectDelay = Math.min(sseReconnectDelay * 2, 15000);
          }
        });

        const refreshAll = () => {
          if (!dashView.hidden) loadDashboard();
          if (!groupView.hidden && currentGroupId) openGroup(currentGroupId);
        };

        sse.addEventListener('registration', (ev) => {
          try {
            const payload = JSON.parse(ev.data);
            const m = payload.member || {};
            const g = payload.group || {};
            Alert.info(
              `${m.name || 'New member'} (${m.regNo || ''}) registered in "${g.name || ''}".` +
                (payload.isLeader ? ' Assigned as Group Leader.' : '') +
                (m.mpesaCode ? ` Paid: ${m.mpesaCode}` : ''),
              { title: 'New registration', timeout: 6000 }
            );
          } catch (_) { /* ignore */ }
          refreshAll();
        });

        sse.addEventListener('registration-status', (ev) => {
          try {
            const payload = JSON.parse(ev.data);
            if (payload && typeof payload.open === 'boolean') {
              renderRegistrationStatus(payload.open);
            }
          } catch (_) { /* ignore */ }
        });

        sse.addEventListener('settings-updated', () => {
          loadSettings();
        });

        ['member-added', 'member-updated', 'member-deleted', 'group-created', 'group-updated', 'group-deleted']
          .forEach((evName) => {
            sse.addEventListener(evName, () => refreshAll());
          });
      } catch (err) {
        console.warn('SSE init failed:', err);
      }
    }

    function stopSse() {
      if (sse) {
        try { sse.close(); } catch (_) {}
        sse = null;
      }
      if (liveIndicator) liveIndicator.hidden = true;
    }

    window.addEventListener('beforeunload', stopSse);

    /* ---- View switching ---- */
    function showLogin() {
      loginView.hidden = false;
      dashView.hidden = true;
      groupView.hidden = true;
      if (logoutBtn) logoutBtn.hidden = true;
      stopSse();
    }
    function showDashboard() {
      loginView.hidden = true;
      dashView.hidden = false;
      groupView.hidden = true;
      if (logoutBtn) logoutBtn.hidden = false;
      history.replaceState(null, '', '/admin-dashboard');
    }
    function showGroup() {
      loginView.hidden = true;
      dashView.hidden = true;
      groupView.hidden = false;
      if (logoutBtn) logoutBtn.hidden = false;
    }

    /* ---- Session check ---- */
    const me = await api('/api/admin/me');
    if (me.ok && me.data && me.data.success) {
      await Promise.all([loadDashboard(), loadSettings()]);
      startSse();
      showDashboard();
    } else {
      showLogin();
    }

    /* ---- Login ---- */
    if (loginForm) {
      loginForm.addEventListener('submit', withLoading(loginBtn, async (e) => {
        e.preventDefault();
        clearFieldErrors(loginForm);
        Alert.clear();

        const username = ($('#adminUsername') || {}).value || '';
        const password = ($('#adminPassword') || {}).value || '';

        if (!username.trim() || !password) {
          Alert.warning('Please enter both username and password.');
          return;
        }

        const { ok, data } = await api('/api/admin/login', {
          method: 'POST',
          body: { username: username.trim(), password },
        });

        if (ok && data && data.success) {
          Alert.success('Welcome, administrator.', { timeout: 2500 });
          loginForm.reset();
          await Promise.all([loadDashboard(), loadSettings()]);
          startSse();
          showDashboard();
        } else {
          Alert.error(
            (data && data.message) || 'Invalid administrator credentials.',
            { title: 'Login failed' }
          );
        }
      }));
    }

    /* ---- Logout ---- */
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async () => {
        const confirmed = await Modal.confirm('Log out of the administrator portal?', {
          title: 'Log out', okText: 'Log out', cancelText: 'Stay',
        });
        if (!confirmed) return;
        const { ok } = await api('/api/admin/logout', { method: 'POST' });
        if (ok) {
          Alert.info('Logged out.', { timeout: 2000 });
          showLogin();
          clearDashboard();
        } else {
          Alert.error('Could not log out.');
        }
      });
    }

    /* ---- Registration toggle button ---- */
    const toggleRegBtn = document.getElementById('btn-toggle-registration');
    if (toggleRegBtn) {
      toggleRegBtn.addEventListener('click', withLoading(toggleRegBtn, async () => {
        const currentPill = document.getElementById('submissions-status-pill');
        const isOpen = currentPill && currentPill.textContent.trim().toUpperCase() === 'OPEN';

        const confirmed = await Modal.confirm(
          isOpen
            ? 'Close student registration submissions? New students will no longer be able to register themselves. You can still add members manually.'
            : 'Open student registration submissions? New students will be able to register themselves immediately.',
          {
            title: isOpen ? 'Close Submissions' : 'Open Submissions',
            okText: isOpen ? 'Close Submissions' : 'Open Submissions',
            cancelText: 'Cancel',
          }
        );
        if (!confirmed) return;

        const { ok, data } = await api('/api/admin/registration-toggle', { method: 'POST' });
        if (ok && data && typeof data.open === 'boolean') {
          renderRegistrationStatus(data.open);
          Alert.success(
            data.message ||
              (data.open
                ? 'Student registration submissions are now OPEN.'
                : 'Student registration submissions are now CLOSED.'),
            { timeout: 3000 }
          );
        } else {
          Alert.error((data && data.message) || 'Could not change registration status.');
        }
      }));
    }

    /* ---- Dashboard ---- */
    async function loadDashboard() {
      const { ok, data } = await api('/api/admin/dashboard');
      if (!ok || !data || !data.success) {
        if (data && data.code === 'AUTH_REQUIRED') { showLogin(); return; }
        Alert.error((data && data.message) || 'Could not load dashboard.');
        return;
      }
      renderDashboard(data);
    }

    function renderDashboard(data) {
      const totals = data.totals || {};
      const groups = data.groups || [];
      const recent = data.recent || [];
      const maxGroupMembers = data.maxGroupMembers || 10;

      window.__peg_lastGroups = groups;

      setText('stat-total-members', totals.totalMembers != null ? totals.totalMembers : 0);
      setText('stat-total-groups', totals.totalGroups != null ? totals.totalGroups : 0);
      setText('stat-total-leaders', totals.totalLeaders != null ? totals.totalLeaders : 0);

      const totalSlots = groups.length * maxGroupMembers;
      const usedSlots = groups.reduce((acc, g) => acc + (g.memberCount || 0), 0);
      const pct = totalSlots > 0 ? Math.round((usedSlots / totalSlots) * 100) : 0;
      setText('stat-capacity-pct', pct + '%');
      setText('stat-capacity-sub', `${usedSlots} / ${totalSlots} slots`);

      const recentBody = document.getElementById('recent-table-body');
      if (recentBody) {
        recentBody.innerHTML = '';
        if (recent.length === 0) {
          recentBody.appendChild(el('tr', {}, [
            el('td', { colspan: '7', class: 'table-empty', text: 'No registrations yet.' }),
          ]));
        } else {
          recent.forEach((m) => {
            const tr = el('tr');
            tr.appendChild(el('td', { text: formatDate(m.createdAt) }));
            tr.appendChild(el('td', { text: m.groupName || '—' }));
            tr.appendChild(el('td', { class: 'mono', text: m.regNo || '' }));
            tr.appendChild(el('td', { text: m.name || '' }));
            tr.appendChild(el('td', { text: m.phone || '' }));
            tr.appendChild(el('td', {}, [
              el('span', {
                class: 'badge ' + (m.isLeader ? 'badge-leader' : 'badge-member'),
                text: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
              }),
            ]));
            tr.appendChild(buildPaymentCell(m));
            recentBody.appendChild(tr);
          });
        }
      }

      const grid = document.getElementById('groups-list');
      if (grid) {
        grid.innerHTML = '';
        if (groups.length === 0) {
          grid.appendChild(el('p', { class: 'muted', text: 'No groups yet. Click "+ New Group" to create one.' }));
        } else {
          groups.forEach((g) => grid.appendChild(buildGroupCard(g, maxGroupMembers)));
        }
      }
    }

    function buildGroupCard(g, maxGroupMembers) {
      const cap = g.capacity || maxGroupMembers || 10;
      const isFull = g.memberCount >= cap;
      return el('button', {
        type: 'button',
        class: 'group-card',
        'data-group-id': g.id,
        onClick: () => openGroup(g.id),
      }, [
        el('div', { class: 'group-card-head' }, [
          el('span', { class: 'group-card-name', text: g.name }),
          el('span', {
            class: 'badge ' + (isFull ? 'badge-full' : 'badge-open'),
            text: isFull ? 'FULL' : 'OPEN',
          }),
        ]),
        el('div', { class: 'group-card-meta' }, [
          el('span', { class: 'group-card-count', text: `${g.memberCount} / ${cap} members` }),
        ]),
        el('div', { class: 'group-card-leader' }, [
          'Leader: ',
          el('strong', { text: g.leaderName || '—' }),
          g.leaderRegNo ? ' (' + g.leaderRegNo + ')' : '',
        ]),
      ]);
    }

    function setText(id, value) {
      const node = document.getElementById(id);
      if (node) node.textContent = String(value);
    }

    function clearDashboard() {
      ['stat-total-members', 'stat-total-groups', 'stat-total-leaders', 'stat-capacity-pct']
        .forEach((id) => setText(id, '0'));
      setText('stat-capacity-sub', '0 / 0 slots');
      const rb = document.getElementById('recent-table-body');
      if (rb) rb.innerHTML = '<tr><td colspan="7" class="table-empty">Loading…</td></tr>';
      const grid = document.getElementById('groups-list');
      if (grid) grid.innerHTML = '<p class="muted">Loading groups…</p>';
    }

    /* ---- Refresh ---- */
    const refreshBtn = document.getElementById('btn-refresh-dashboard');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', withLoading(refreshBtn, async () => {
        await Promise.all([loadDashboard(), loadSettings()]);
        Alert.success('Refreshed.', { timeout: 1500 });
      }));
    }

    /* ---- Create group ---- */
    const createGroupBtn = document.getElementById('btn-create-group');
    if (createGroupBtn) {
      createGroupBtn.addEventListener('click', () => openGroupModal(null));
    }

    function openGroupModal(existing) {
      const form = document.getElementById('group-form');
      const title = document.getElementById('modal-group-title');
      const idInput = document.getElementById('group-edit-id');
      const nameInput = document.getElementById('group-name-input');
      clearFieldErrors(form);

      if (existing) {
        if (title) title.textContent = 'Rename Group';
        if (idInput) idInput.value = existing.id;
        if (nameInput) nameInput.value = existing.name;
      } else {
        if (title) title.textContent = 'Create Group';
        if (idInput) idInput.value = '';
        if (nameInput) nameInput.value = '';
      }
      Modal.open('modal-group');
    }

    const groupForm = document.getElementById('group-form');
    const groupSubmitBtn = document.getElementById('group-submit-btn');
    if (groupForm) {
      groupForm.addEventListener('submit', withLoading(groupSubmitBtn, async (e) => {
        e.preventDefault();
        clearFieldErrors(groupForm);

        const id = (document.getElementById('group-edit-id') || {}).value || '';
        const name = ((document.getElementById('group-name-input') || {}).value || '').trim();

        if (!name) {
          setFieldError('group-name-input', 'Group name is required.');
          return;
        }

        const { ok, data } = id
          ? await api(`/api/admin/groups/${encodeURIComponent(id)}`, {
              method: 'PATCH', body: { name },
            })
          : await api('/api/admin/groups', {
              method: 'POST', body: { name },
            });

        if (ok && data && data.success) {
          Modal.close('modal-group');
          Alert.success(data.message || 'Saved.', { timeout: 2200 });
          await loadDashboard();
          if (id && currentGroupId === id) await openGroup(id);
        } else {
          const msg = (data && data.message) || 'Could not save group.';
          if (data && data.code === 'DUPLICATE_GROUP') {
            setFieldError('group-name-input', 'That name is already in use.');
          }
          Alert.error(msg);
        }
      }));
    }

    /* ---- Group detail ---- */
    async function openGroup(groupId) {
      currentGroupId = groupId;
      const { ok, data } = await api(`/api/admin/groups/${encodeURIComponent(groupId)}`);
      if (!ok || !data || !data.success) {
        if (data && data.code === 'AUTH_REQUIRED') { showLogin(); return; }
        Alert.error((data && data.message) || 'Could not load group.');
        return;
      }
      currentGroupData = data;
      renderGroupDetail(data);
      showGroup();
      history.replaceState(null, '', `/admin-group?id=${encodeURIComponent(groupId)}`);
    }

    function renderGroupDetail(data) {
      const group = data.group || {};
      const members = data.members || [];

      setText('group-title', group.name || 'Group');
      setText('group-sub', `Group ID: ${group.id} · Created ${formatDateShort(group.createdAt)}`);
      setText('group-member-count', group.memberCount != null ? group.memberCount : members.length);
      setText('group-capacity', group.capacity || 10);
      setText('group-leader-name', group.leaderName || '—');
      setText('group-leader-regno', group.leaderRegNo ? `REG: ${group.leaderRegNo}` : '');
      setText('group-created', formatDateShort(group.createdAt));
      const statusEl = document.getElementById('group-status');
      if (statusEl) {
        const isFull = (group.memberCount || members.length) >= (group.capacity || 10);
        statusEl.innerHTML = '';
        statusEl.appendChild(el('span', {
          class: 'badge ' + (isFull ? 'badge-full' : 'badge-open'),
          text: isFull ? 'FULL' : 'OPEN',
        }));
      }

      const tbody = document.getElementById('group-members-body');
      if (!tbody) return;
      tbody.innerHTML = '';

      if (members.length === 0) {
        tbody.appendChild(el('tr', {}, [
          el('td', { colspan: '7', class: 'table-empty', text: 'No members in this group yet.' }),
        ]));
        return;
      }

      members.forEach((m, i) => {
        const tr = el('tr', { class: m.isLeader ? 'is-leader' : '' });
        tr.appendChild(el('td', { text: String(i + 1) }));
        tr.appendChild(el('td', { class: 'mono', text: m.regNo }));
        tr.appendChild(el('td', { text: m.name }));
        tr.appendChild(el('td', { text: m.phone }));
        tr.appendChild(el('td', {}, [
          el('span', {
            class: 'badge ' + (m.isLeader ? 'badge-leader' : 'badge-member'),
            text: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
          }),
        ]));
        tr.appendChild(buildPaymentCell(m));
        tr.appendChild(el('td', {}, [
          el('div', { class: 'row-actions' }, [
            el('button', {
              type: 'button', class: 'btn btn-ghost btn-icon',
              onClick: () => openMemberModal(m, group.id),
            }, ['Edit']),
            el('button', {
              type: 'button', class: 'btn btn-danger-outline btn-icon',
              onClick: () => deleteMember(m),
            }, ['Delete']),
          ]),
        ]));
        tbody.appendChild(tr);
      });
    }

    const backBtn = document.getElementById('btn-back-dashboard');
    if (backBtn) {
      backBtn.addEventListener('click', async () => {
        currentGroupId = null;
        await loadDashboard();
        showDashboard();
      });
    }

    const renameBtn = document.getElementById('btn-rename-group');
    if (renameBtn) {
      renameBtn.addEventListener('click', () => {
        if (!currentGroupData) return;
        openGroupModal(currentGroupData.group);
      });
    }

    const deleteGroupBtn = document.getElementById('btn-delete-group');
    if (deleteGroupBtn) {
      deleteGroupBtn.addEventListener('click', async () => {
        if (!currentGroupData) return;
        const group = currentGroupData.group;
        const memberCount = group.memberCount || 0;

        let message = `Are you sure you want to delete "${group.name}"?`;
        if (memberCount > 0) {
          message = `"${group.name}" contains ${memberCount} member(s). Deleting the group will ALSO delete all of its members. Are you sure?`;
        }
        const confirmed = await Modal.confirm(message, {
          title: 'Delete Group', okText: 'Delete', cancelText: 'Cancel',
        });
        if (!confirmed) return;

        const url = `/api/admin/groups/${encodeURIComponent(group.id)}?confirm=true`;
        const { ok, data } = await api(url, { method: 'DELETE' });

        if (ok && data && data.success) {
          Alert.success(data.message || 'Group deleted.', { timeout: 2500 });
          currentGroupId = null;
          await loadDashboard();
          showDashboard();
        } else {
          Alert.error((data && data.message) || 'Could not delete group.');
        }
      });
    }

    const addMemberBtn = document.getElementById('btn-add-member');
    if (addMemberBtn) {
      addMemberBtn.addEventListener('click', () => {
        if (!currentGroupData) return;
        openMemberModal(null, currentGroupData.group.id);
      });
    }

    function openMemberModal(member, presetGroupId) {
      const form = document.getElementById('member-form');
      const title = document.getElementById('modal-member-title');
      clearFieldErrors(form);

      const idInput = document.getElementById('member-edit-id');
      const regInput = document.getElementById('member-regNo');
      const nameInput = document.getElementById('member-name');
      const phoneInput = document.getElementById('member-phone');
      const groupSelect = document.getElementById('member-group');
      const mpesaInput = document.getElementById('member-mpesa');
      const noteInput = document.getElementById('member-payment-note');

      if (groupSelect) {
        groupSelect.innerHTML = '';
        const list = window.__peg_lastGroups || (currentGroupData && currentGroupData.group ? [currentGroupData.group] : []);
        for (const g of list) {
          const opt = el('option', {
            value: g.id,
            text: `${g.name} (${g.memberCount}/${g.capacity || 10})`,
          });
          if (g.id === presetGroupId) opt.selected = true;
          groupSelect.appendChild(opt);
        }
      }

      if (member) {
        if (title) title.textContent = 'Edit Member';
        if (idInput) idInput.value = member.id;
        if (regInput) regInput.value = member.regNo;
        if (nameInput) nameInput.value = member.name;
        if (phoneInput) phoneInput.value = member.phone;
        if (groupSelect) groupSelect.value = presetGroupId;
        if (mpesaInput) mpesaInput.value = member.mpesaCode || '';
        if (noteInput) noteInput.value = member.paymentNote || '';
      } else {
        if (title) title.textContent = 'Add Member';
        if (idInput) idInput.value = '';
        if (regInput) regInput.value = '';
        if (nameInput) nameInput.value = '';
        if (phoneInput) phoneInput.value = '';
        if (groupSelect) groupSelect.value = presetGroupId || '';
        if (mpesaInput) mpesaInput.value = '';
        if (noteInput) noteInput.value = '';
      }
      Modal.open('modal-member');
    }

    const memberForm = document.getElementById('member-form');
    const memberSubmitBtn = document.getElementById('member-submit-btn');
    if (memberForm) {
      memberForm.addEventListener('submit', withLoading(memberSubmitBtn, async (e) => {
        e.preventDefault();
        clearFieldErrors(memberForm);

        const id = (document.getElementById('member-edit-id') || {}).value || '';
        const regNo = ((document.getElementById('member-regNo') || {}).value || '').trim();
        const name = ((document.getElementById('member-name') || {}).value || '').trim();
        const phone = ((document.getElementById('member-phone') || {}).value || '').trim();
        const groupId = ((document.getElementById('member-group') || {}).value || '').trim();
        const mpesaCode = ((document.getElementById('member-mpesa') || {}).value || '').trim().toUpperCase();
        const paymentNote = ((document.getElementById('member-payment-note') || {}).value || '').trim();

        let hasError = false;
        if (!regNo) { setFieldError('member-regNo', 'Registration number is required.'); hasError = true; }
        if (!name) { setFieldError('member-name', 'Full name is required.'); hasError = true; }
        if (!phone) { setFieldError('member-phone', 'Phone number is required.'); hasError = true; }
        if (!groupId) { setFieldError('member-group', 'Group is required.'); hasError = true; }
        if (mpesaCode && !/^[A-Z0-9]{10}$/.test(mpesaCode)) {
          setFieldError('member-mpesa', 'M-Pesa code must be 10 characters (A–Z, 0–9).');
          hasError = true;
        }
        if (hasError) return;

        const payload = {
          regNo,
          name,
          phone,
          groupId,
          mpesaCode: mpesaCode || '',
          paymentNote: paymentNote || '',
        };

        const { ok, data } = id
          ? await api(`/api/admin/members/${encodeURIComponent(id)}`, { method: 'PATCH', body: payload })
          : await api('/api/admin/members', { method: 'POST', body: payload });

        if (ok && data && data.success) {
          Modal.close('modal-member');
          Alert.success(data.message || 'Saved.', { timeout: 2200 });
          if (currentGroupId) await openGroup(currentGroupId);
          await loadDashboard();
        } else {
          const code = (data && data.code) || '';
          const msg = (data && data.message) || 'Could not save member.';
          if (code === 'DUPLICATE_REGNO') setFieldError('member-regNo', 'Already registered.');
          else if (code === 'INVALID_PHONE') setFieldError('member-phone', 'Invalid phone number.');
          Alert.error(msg);
        }
      }));
    }

    async function deleteMember(member) {
      const confirmed = await Modal.confirm(
        `Delete "${member.name}" (${member.regNo})? This cannot be undone.`,
        { title: 'Delete Member', okText: 'Delete', cancelText: 'Cancel' }
      );
      if (!confirmed) return;

      const { ok, data } = await api(`/api/admin/members/${encodeURIComponent(member.id)}`, {
        method: 'DELETE',
      });

      if (ok && data && data.success) {
        Alert.success('Member deleted.', { timeout: 2000 });
        if (currentGroupId) await openGroup(currentGroupId);
        await loadDashboard();
      } else {
        Alert.error((data && data.message) || 'Could not delete member.');
      }
    }

    /* ---- Export links: blur on click so the button doesn't stay focused ---- */
    ['btn-export-csv', 'btn-export-pdf', 'btn-export-paid-pdf'].forEach((id) => {
      const link = document.getElementById(id);
      if (link) link.addEventListener('click', (e) => e.currentTarget.blur());
    });

    /* ---- Deep link: /admin-group?id=xxx ---- */
    const params = new URLSearchParams(window.location.search);
    const qsId = params.get('id');
    if (qsId && me.ok && me.data && me.data.success) {
      openGroup(qsId);
    }

    window.__peg_admin = { loadDashboard, openGroup };
  }

  /* ============================================================
   * 14. Auto-bootstrap by page
   * ============================================================ */
  function bootstrap() {
    wireVisibilityToggles();

    getCsrfToken().catch(() => {});

    const yearEl = document.getElementById('footer-year');
    if (yearEl) yearEl.textContent = String(new Date().getFullYear());

    if (document.getElementById('register-form')) {
      initRegisterPage();
    }

    if (document.getElementById('member-login-form')) {
      initMemberPage().catch((err) => {
        console.error('[PEG] initMemberPage failed:', err);
      });
    }

    if (document.getElementById('admin-login-form')) {
      initAdminPage().catch((err) => {
        console.error('[PEG] initAdminPage failed:', err);
      });
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }

  /* ============================================================
   * 15. Public API
   * ============================================================ */
  window.PEG = window.PEG || {};
  window.PEG.initMemberPage = initMemberPage;
  window.PEG.initAdminPage = initAdminPage;
  window.PEG.device = Device;
  window.PEG.api = api;
  window.PEG.alert = Alert;
  window.PEG.modal = Modal;

})();

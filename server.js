'use strict';

/* ============================================================================
 * ============================================================================
 *                                                                            *
 *   ██████╗ ██╗  ██╗██╗   ██╗███████╗██╗ ██████╗███████╗                      *
 *   ██╔══██╗██║  ██║╚██╗ ██╔╝██╔════╝██║██╔════╝██╔════╝                      *
 *   ██████╔╝███████║ ╚████╔╝ ███████╗██║██║     ███████╗                      *
 *   ██╔═══╝ ██╔══██║  ╚██╔╝  ╚════██║██║██║     ╚════██║                      *
 *   ██║     ██║  ██║   ██║   ███████║██║╚██████╗███████║                      *
 *   ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝ ╚═════╝╚══════╝                      *
 *                                                                            *
 *   EDUCATION GROUPS — BACKEND SERVICE                                       *
 *   File: server.js                                                          *
 *   Version: 1.5.0                                                           *
 *   Runtime: Node.js >= 18.17                                                *
 *   Framework: Express 4                                                     *
 *   Database: MongoDB Atlas via Mongoose 8                                   *
 *   Deployment: Render (npm start)                                           *
 *                                                                            *
 * ============================================================================
 * ============================================================================
 *
 *  TABLE OF CONTENTS
 *  -----------------
 *   SECTION 1  — ENVIRONMENT & BOOTSTRAP
 *   SECTION 2  — UTILITIES & HELPERS
 *   SECTION 3  — M-PESA SMS EXTRACTOR
 *   SECTION 4  — DATABASE CONNECTION
 *   SECTION 5  — MONGOOSE MODELS
 *   SECTION 6  — SETTINGS & BUSINESS HELPERS
 *   SECTION 7  — SERVER-SENT EVENTS (SSE)
 *   SECTION 8  — EXPRESS APP & MIDDLEWARE
 *   SECTION 9  — PUBLIC ROUTES
 *   SECTION 10 — MEMBER ROUTES
 *   SECTION 11 — ADMIN ROUTES
 *   SECTION 12 — CSV EXPORT
 *   SECTION 13 — PDF EXPORT
 *   SECTION 14 — SSE ENDPOINT
 *   SECTION 15 — STATIC FILES & PAGE ROUTES
 *   SECTION 16 — 404 & ERROR HANDLERS
 *   SECTION 17 — SERVER STARTUP & SHUTDOWN
 *
 *  CHANGE LOG
 *  ----------
 *   v1.0.0 — Initial release. Basic registration, groups, members, admin.
 *   v1.1.0 — Added PDF export, admin dashboard, SSE, leader reconciliation.
 *   v1.2.0 — Added registration open/close toggle, Settings collection,
 *             muted professional PDF colors.
 *   v1.3.0 — Added configurable max group members (1–20), M-Pesa code
 *             capture fields, payment-config public endpoint.
 *   v1.4.0 — Added paid-PDF export, separate clean PDF/CSV from payment
 *             data, paid-summary endpoint.
 *   v1.5.0 — Added admin paste-and-verify workflow (M-Pesa SMS extractor),
 *             paymentStatus enum (pending/verified/rejected), unique
 *             mpesaCode sparse index, pending-payments listing, per-member
 *             verify/reject endpoints, hard M-Pesa code validation,
 *             duplicate M-Pesa code rejection.
 *
 *  ARCHITECTURE NOTES
 *  ------------------
 *   This is a single-file Express backend. All routes, models, middleware,
 *   and business logic are contained here for simplicity of deployment to
 *   Render. There is no separate build step, no transpilation, and no
 *   external state beyond MongoDB.
 *
 *   Data flow for public registration:
 *     1. Client posts { regNo, name, phone, groupName, deviceId,
 *                       deviceMetadata, [mpesaCode, paymentNote] }.
 *     2. Server reads current settings (open/closed, payment required,
 *        amount, phone, max members).
 *     3. Server validates every field.
 *     4. If payment proof required: validates M-Pesa code format, checks
 *        for duplicates, stores code with status 'pending'.
 *     5. Server finds or creates the group (case/whitespace normalized).
 *     6. Server performs an ATOMIC findOneAndUpdate on the group to
 *        increment memberCount only if below the current max. This
 *        eliminates race conditions when two members register at once
 *        for the last available slot.
 *     7. Server inserts the Member document. On failure, it rolls back
 *        the capacity increment.
 *     8. If this was the first member, it becomes the Group Leader.
 *     9. Server broadcasts an SSE 'registration' event for the admin
 *        dashboard.
 *    10. Server responds with the created member + group + payment info.
 *
 *   Data flow for admin payment verification:
 *     1. Admin pastes one or more M-Pesa SMS messages into a textarea.
 *     2. Client POSTs { text: '<pasted content>' } to
 *        /api/admin/verify-payments.
 *     3. Server extracts every 10-char alphanumeric token that looks
 *        like an M-Pesa code (near the word 'Confirmed' or at a line
 *        boundary).
 *     4. For each extracted code:
 *          a. Look for a member with that exact mpesaCode.
 *          b. If not found, extract the sender phone from the surrounding
 *             text and look for a unique member with that phone.
 *          c. If still ambiguous, report it back to the admin.
 *     5. Matched members get paymentStatus = 'verified', and
 *        paymentVerifiedAt / paymentVerifiedBy are stamped.
 *     6. Server returns a breakdown of verified / already / unmatched /
 *        ambiguous entries for the admin to review.
 *
 *  SECURITY LAYERS
 *  ---------------
 *   - Helmet: sets Content-Security-Policy, X-Frame-Options,
 *     X-Content-Type-Options, Referrer-Policy, HSTS (in production).
 *   - CORS: same-origin by default; explicit allow-list via CORS_ORIGIN.
 *   - Cookie parser: enables HTTP-only session cookies.
 *   - Rate limiting: general (400/15min), register (25/15min),
 *     login (25/15min). Applies to /api/* routes.
 *   - CSRF: double-submit cookie. A token is issued at /api/csrf-token
 *     and must be echoed in the X-CSRF-Token header on every mutating
 *     request (POST, PATCH, DELETE).
 *   - Auth: HTTP-only cookies holding an opaque session token stored in
 *     the AdminSession collection. Admin and member sessions are
 *     separate cookies.
 *   - Password hashing: scrypt with a random 16-byte salt and 64-byte
 *     key. Timing-safe comparison.
 *   - Device fingerprint: browser-generated ID stored with each member;
 *     unique sparse index prevents duplicate registrations from the
 *     same device.
 *   - Unique REG number and unique M-Pesa code, both enforced by
 *     MongoDB unique indexes.
 *   - No raw IP storage: an optional HMAC-SHA256 hash (keyed with
 *     SESSION_SECRET) can be stored instead.
 *   - Centralized error handler: strips stack traces and Mongo internals
 *     from user-visible responses.
 *
 * ============================================================================
 */

// ============================================================================
// MODULE IMPORTS
// ============================================================================
// All imports are at the top so their presence is obvious and the rest of
// the file can assume they exist. We deliberately avoid importing anything
// that isn't strictly necessary — no lodash, no uuid, no bcrypt (Node's
// built-in crypto provides scrypt which is sufficient).

const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const http = require('http');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');
const PDFDocument = require('pdfkit');

/* ============================================================================
 * SECTION 1 — ENVIRONMENT & BOOTSTRAP
 * ============================================================================
 *
 * Responsibilities:
 *   - Load .env if present (development convenience).
 *   - Read every environment variable into a strongly-typed constant.
 *   - Validate required variables and fail fast with a clear message.
 *   - Expose a frozen CONFIG object used everywhere else.
 *
 * Never logs secrets (SESSION_SECRET, ADMIN_PASSWORD, MONGODB_URI contents).
 * ========================================================================== */

/**
 * Load a .env file from the current working directory if one exists.
 * In production (Render), environment variables are injected directly
 * into process.env, so this is a no-op there.
 *
 * Failure to load .env is a warning, not an error: the app can still run
 * if the environment variables were set externally.
 */
(function loadDotenv() {
  try {
    const dotenv = require('dotenv');
    const envPath = path.resolve(process.cwd(), '.env');
    if (fs.existsSync(envPath)) {
      const result = dotenv.config({ path: envPath });
      if (result.error) {
        console.warn('[env] Warning: could not load .env —', result.error.message);
      }
    }
  } catch (_) {
    console.warn('[env] dotenv not available, using process.env only.');
  }
})();

/**
 * Read an environment variable as a trimmed string.
 * @param {string} key - The variable name.
 * @param {string} [fallback=''] - Value to use when the variable is unset.
 * @returns {string}
 */
const readString = (key, fallback = '') => {
  const v = process.env[key];
  return v == null ? fallback : String(v).trim();
};

/**
 * Read an environment variable as a boolean.
 * Accepts 1/true/yes/on/enabled (case-insensitive) as truthy.
 * Accepts 0/false/no/off/disabled/empty as falsy.
 * @param {string} key - The variable name.
 * @param {boolean} [fallback=false] - Value when unset or unparseable.
 * @returns {boolean}
 */
const readBool = (key, fallback = false) => {
  const v = readString(key, String(fallback)).toLowerCase();
  if (['1', 'true', 'yes', 'on', 'enabled'].includes(v)) return true;
  if (['0', 'false', 'no', 'off', 'disabled', ''].includes(v)) return false;
  return fallback;
};

/**
 * Read an environment variable as a base-10 integer.
 * @param {string} key - The variable name.
 * @param {number} [fallback=0] - Value when unset or unparseable.
 * @returns {number}
 */
const readInt = (key, fallback = 0) => {
  const v = readString(key, String(fallback));
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : fallback;
};

/**
 * Read an environment variable as a comma-separated list of strings.
 * Trims each entry and drops empty values.
 * @param {string} key - The variable name.
 * @param {string[]} [fallback=[]] - Value when unset.
 * @returns {string[]}
 */
const readList = (key, fallback = []) => {
  const v = readString(key, '');
  if (!v) return fallback;
  return v.split(',').map((s) => s.trim()).filter(Boolean);
};

// ----------------------------------------------------------------------------
// Read environment into local constants
// ----------------------------------------------------------------------------

const NODE_ENV = readString('NODE_ENV', 'development') || 'development';
const IS_PROD = NODE_ENV === 'production';
const IS_DEV = NODE_ENV === 'development';

const PORT = readInt('PORT', 10000);

const MONGODB_URI = readString('MONGODB_URI');

const ADMIN_USERNAME = readString('ADMIN_USERNAME', 'administrator123');
const ADMIN_PASSWORD = readString('ADMIN_PASSWORD', '1234567890');

const SESSION_SECRET_RAW = readString('SESSION_SECRET');

const CORS_ORIGIN = readList('CORS_ORIGIN', []);
const STORE_IP_HASH = readBool('STORE_IP_HASH', false);
const ENFORCE_DEVICE_LOCK = readBool('ENFORCE_DEVICE_LOCK', true);

// ----------------------------------------------------------------------------
// Fail-fast validation
// ----------------------------------------------------------------------------
//
// We validate at startup so that misconfiguration is caught before the
// server binds to a port. This avoids the situation where Render reports
// "deployed" but every request errors because a required variable is
// missing.

if (!MONGODB_URI) {
  console.error('\n[env] FATAL: MONGODB_URI is required.\n');
  process.exit(1);
}
if (!/^mongodb(\+srv)?:\/\//i.test(MONGODB_URI)) {
  console.error('\n[env] FATAL: MONGODB_URI must start with mongodb:// or mongodb+srv://\n');
  process.exit(1);
}
if (IS_PROD && (!SESSION_SECRET_RAW || SESSION_SECRET_RAW.length < 24)) {
  console.error('\n[env] FATAL: SESSION_SECRET (>=24 chars) is required in production.\n');
  process.exit(1);
}

/**
 * Effective session secret.
 * Uses the environment value if it is at least 24 characters; otherwise
 * generates a fresh random secret for development. In production we
 * have already exited above if the value is missing/short.
 */
const SESSION_SECRET =
  SESSION_SECRET_RAW && SESSION_SECRET_RAW.length >= 24
    ? SESSION_SECRET_RAW
    : crypto.randomBytes(48).toString('hex');

/**
 * Frozen application configuration.
 * All fields are read-only. If you need to change behaviour, change the
 * environment variables and restart the server.
 */
const CONFIG = Object.freeze({
  NODE_ENV,
  IS_PROD,
  IS_DEV,
  PORT,
  MONGODB_URI,
  ADMIN_USERNAME,
  ADMIN_PASSWORD,
  SESSION_SECRET,
  CORS_ORIGIN,
  STORE_IP_HASH,
  ENFORCE_DEVICE_LOCK,

  // Absolute ceiling on group size — the effective cap is stored in the
  // Settings collection under 'max_group_members' (admin-configurable).
  MAX_GROUP_MEMBERS_HARD_LIMIT: 20,
  MAX_GROUP_MEMBERS_DEFAULT: 10,

  // Cookie names
  ADMIN_COOKIE: 'peg_admin_sid',
  MEMBER_COOKIE: 'peg_member_sid',
  CSRF_COOKIE: 'peg_csrf',
  CSRF_HEADER: 'x-csrf-token',

  // Session lifetimes (milliseconds)
  ADMIN_SESSION_TTL_MS: 8 * 60 * 60 * 1000,   // 8 hours
  MEMBER_SESSION_TTL_MS: 12 * 60 * 60 * 1000, // 12 hours
  CSRF_TTL_MS: 4 * 60 * 60 * 1000,            // 4 hours

  // Cookie flags
  COOKIE_SECURE: IS_PROD,
  COOKIE_SAME_SITE: 'strict',
});

console.log(`[boot] Physics Education Groups starting in ${NODE_ENV} mode on port ${PORT}.`);

/* ============================================================================
 * SECTION 2 — UTILITIES & HELPERS
 * ============================================================================
 *
 * Pure functions with no side effects. These are used throughout the
 * application for input normalization, validation, password hashing,
 * and response shaping.
 *
 * Every function here is safe to call with null or undefined input.
 * ========================================================================== */

// ----------------------------------------------------------------------------
// Logging helpers
// ----------------------------------------------------------------------------
//
// Consistent prefixes make it easy to grep Render logs for a specific
// category. We never log secrets.

/**
 * Log an informational message with the standard [peg] prefix.
 * @param {...any} args
 */
function logInfo(...args) {
  // eslint-disable-next-line no-console
  console.log('[peg]', ...args);
}

/**
 * Log a warning with the standard [peg] prefix.
 * @param {...any} args
 */
function logWarn(...args) {
  // eslint-disable-next-line no-console
  console.warn('[peg]', ...args);
}

/**
 * Log an error with the standard [peg] prefix.
 * @param {...any} args
 */
function logError(...args) {
  // eslint-disable-next-line no-console
  console.error('[peg]', ...args);
}

/**
 * Truncate a string to a maximum length, appending an ellipsis if cut.
 * Safe on null/undefined (returns '').
 * @param {any} value
 * @param {number} [max=120]
 * @returns {string}
 */
function truncate(value, max = 120) {
  if (value == null) return '';
  const s = String(value);
  if (s.length <= max) return s;
  return s.slice(0, Math.max(0, max - 1)) + '…';
}

/**
 * Format a byte count into a human-readable string.
 * @param {number} bytes
 * @returns {string}
 */
function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 2 : 0)} ${units[i]}`;
}

/**
 * Return the current time as an ISO 8601 string.
 * @returns {string}
 */
function nowIso() {
  return new Date().toISOString();
}

/**
 * Pick a subset of keys from an object.
 * @param {object} obj
 * @param {string[]} keys
 * @returns {object}
 */
function pick(obj, keys) {
  const out = {};
  if (!obj || typeof obj !== 'object') return out;
  for (const k of keys) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) out[k] = obj[k];
  }
  return out;
}

/**
 * Return a copy of an object without the specified keys.
 * @param {object} obj
 * @param {string[]} keys
 * @returns {object}
 */
function omit(obj, keys) {
  const out = {};
  if (!obj || typeof obj !== 'object') return out;
  const exclude = new Set(keys);
  for (const k of Object.keys(obj)) {
    if (!exclude.has(k)) out[k] = obj[k];
  }
  return out;
}

/**
 * Safe JSON parse. Returns the fallback on any error.
 * @param {string} text
 * @param {any} [fallback=null]
 * @returns {any}
 */
function safeJsonParse(text, fallback = null) {
  try { return JSON.parse(text); }
  catch (_) { return fallback; }
}

// ----------------------------------------------------------------------------
// Group name normalization
// ----------------------------------------------------------------------------

/**
 * Normalize a group name for comparison.
 *
 * Steps:
 *   1. Strip control characters.
 *   2. Collapse runs of whitespace into a single space.
 *   3. Trim leading/trailing whitespace.
 *   4. Lowercase.
 *
 * Examples:
 *   "  Group A  "    → "group a"
 *   "GROUP   A"      → "group a"
 *   "Group\tA\n"     → "group a"
 *
 * @param {any} raw
 * @returns {string}
 */
function normalizeGroupName(raw) {
  if (raw == null) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toLowerCase();
}

/**
 * Prepare a group name for display: strips control characters, collapses
 * whitespace, trims, but preserves the user's original casing.
 * @param {any} raw
 * @returns {string}
 */
function displayGroupName(raw) {
  if (raw == null) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

// ----------------------------------------------------------------------------
// Registration number normalization
// ----------------------------------------------------------------------------

/**
 * Normalize a registration number.
 * Trims, removes whitespace, uppercases.
 * @param {any} raw
 * @returns {string}
 */
function normalizeRegNo(raw) {
  if (raw == null) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toUpperCase();
}

// ----------------------------------------------------------------------------
// Person name normalization
// ----------------------------------------------------------------------------

/**
 * Normalize a person's name: strips control characters and collapses
 * internal whitespace but preserves casing and punctuation.
 * @param {any} raw
 * @returns {string}
 */
function normalizeName(raw) {
  if (raw == null) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

// ----------------------------------------------------------------------------
// Phone normalization
// ----------------------------------------------------------------------------

/**
 * Normalize a Kenyan phone number to E.164 (+2547XXXXXXXX or +2541XXXXXXXX).
 *
 * Accepts:
 *   0712345678
 *   0112345678
 *   254712345678
 *   254112345678
 *   +254712345678
 *   +254112345678
 *
 * @param {any} raw
 * @returns {string|null}  E.164 form, or null if unparseable.
 */
function normalizePhone(raw) {
  if (raw == null) return null;
  let s = String(raw).replace(/[\s\-().]/g, '');
  if (s.startsWith('+')) s = s.slice(1);
  if (/^254(7|1)\d{8}$/.test(s)) return '+' + s;
  if (/^0(7|1)\d{8}$/.test(s)) return '+254' + s.slice(1);
  return null;
}

/**
 * Alias used when the phone number represents the payment destination
 * (Pochi). Same normalization as a regular phone.
 * @param {any} raw
 * @returns {string|null}
 */
function normalizePochiPhone(raw) {
  return normalizePhone(raw);
}

// ----------------------------------------------------------------------------
// Device ID validation
// ----------------------------------------------------------------------------

/**
 * Validate a device fingerprint ID.
 * Must be 8–128 chars, alphanumeric plus - _ :
 * @param {any} id
 * @returns {boolean}
 */
function isValidDeviceId(id) {
  if (!id || typeof id !== 'string') return false;
  const t = id.trim();
  if (t.length < 8 || t.length > 128) return false;
  return /^[A-Za-z0-9_\-:]+$/.test(t);
}

// ----------------------------------------------------------------------------
// Field validators
// ----------------------------------------------------------------------------

/**
 * Is the given value a usable group name?
 * @param {any} raw
 * @returns {boolean}
 */
function isValidGroupName(raw) {
  const n = normalizeGroupName(raw);
  return Boolean(n) && n.length <= 80;
}

/**
 * Is the given value a usable registration number?
 * Allowed: A–Z, 0–9, -, /, _, .
 * @param {any} raw
 * @returns {boolean}
 */
function isValidRegNo(raw) {
  const n = normalizeRegNo(raw);
  if (n.length < 3 || n.length > 40) return false;
  return /^[A-Z0-9\-\/_.]+$/.test(n);
}

/**
 * Is the given value a usable person name?
 * Allows letters (any script), marks, digits, space, ., ,, ', -, (, ).
 * @param {any} raw
 * @returns {boolean}
 */
function isValidName(raw) {
  const n = normalizeName(raw);
  if (n.length < 2 || n.length > 120) return false;
  return /^[\p{L}\p{M}0-9 .,'\-()]+$/u.test(n);
}

/**
 * Is the given value a valid Kenyan phone number?
 * @param {any} raw
 * @returns {boolean}
 */
function isValidKenyanPhone(raw) {
  return normalizePhone(raw) !== null;
}

// ----------------------------------------------------------------------------
// M-Pesa code normalization & hard validation
// ----------------------------------------------------------------------------

/**
 * Normalize an M-Pesa confirmation code.
 * Trims, removes whitespace, uppercases.
 * @param {any} raw
 * @returns {string}
 */
function normalizeMpesaCode(raw) {
  if (raw == null) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, '')
    .trim()
    .toUpperCase();
}

/**
 * Perform hard validation of an M-Pesa code.
 *
 * Real M-Pesa confirmation codes are 10 characters long, mix letters and
 * digits, and never form obvious patterns. This function rejects:
 *   - Wrong length
 *   - Non-alphanumeric characters
 *   - Missing letters or missing digits
 *   - All-same-character strings (AAAAAAAAAA)
 *   - Runs of the same character (AAAAABCDEF)
 *   - Well-known sequential patterns (1234567890, ABCDEFGHIJ, QWERTYUIOP)
 *   - Codes containing common fake words (TEST, FAKE, PAID, MONEY, etc.)
 *
 * This is NOT a live verification. It only rejects obvious fakes. The
 * admin's paste-and-verify workflow is the authoritative check.
 *
 * @param {any} rawCode
 * @returns {{valid: boolean, code?: string, reason?: string}}
 */
function validateMpesaCodeHard(rawCode) {
  const code = normalizeMpesaCode(rawCode);

  if (!code) return { valid: false, reason: 'M-Pesa code is required.' };

  if (code.length !== 10) {
    return { valid: false, reason: 'M-Pesa code must be exactly 10 characters.' };
  }

  if (!/^[A-Z0-9]{10}$/.test(code)) {
    return { valid: false, reason: 'M-Pesa code can only contain letters A–Z and digits 0–9.' };
  }

  if (!/[A-Z]/.test(code)) {
    return { valid: false, reason: 'M-Pesa code must contain at least one letter.' };
  }

  if (!/[0-9]/.test(code)) {
    return { valid: false, reason: 'M-Pesa code must contain at least one digit.' };
  }

  // All-same-character: AAAAAAAAAA
  if (/^(.)\1+$/.test(code)) {
    return { valid: false, reason: 'M-Pesa code cannot be a repeated character.' };
  }

  // First five characters identical: AAAAABCDEF
  if (/^(.)\1{4}/.test(code)) {
    return { valid: false, reason: 'This code looks invalid. Please enter the code from your M-Pesa SMS.' };
  }

  // Known sequential/keyboard patterns
  const badPatterns = [
    '0123456789', '1234567890', '0987654321', '9876543210',
    'ABCDEFGHIJ', 'BCDEFGHIJK', 'JIHGFEDCBA', 'KJIHGFEDCB',
    'QWERTYUIOP', 'ASDFGHJKLZ', 'ZXCVBNMLKJ', 'POIUYTREWQ',
  ];
  for (const p of badPatterns) {
    if (code === p) return { valid: false, reason: 'This is a pattern, not a real M-Pesa code.' };
    if (code.includes(p.slice(0, 6))) {
      return { valid: false, reason: 'This looks like a pattern. Enter the code from your SMS.' };
    }
  }

  // Common fake words that appear in made-up codes
  const fakeWords = ['TEST', 'FAKE', 'PAID', 'MONEY', 'ADMIN', 'LUCKY', 'TRUST'];
  for (const w of fakeWords) {
    if (code.includes(w)) {
      return { valid: false, reason: 'This looks like a made-up code. Enter the code from your SMS.' };
    }
  }

  return { valid: true, code };
}

// ----------------------------------------------------------------------------
// Payment note sanitization
// ----------------------------------------------------------------------------

/**
 * Sanitize the free-text payment note the student enters (time & day
 * they paid). Caps at 200 characters.
 * @param {any} raw
 * @returns {string}
 */
function sanitizePaymentNote(raw) {
  if (raw == null) return '';
  return String(raw)
    .replace(/[\u0000-\u001F\u007F]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 200);
}

// ----------------------------------------------------------------------------
// Device metadata sanitization
// ----------------------------------------------------------------------------

/**
 * Sanitize non-sensitive device metadata. Only known keys are kept,
 * strings are length-capped, and only primitive values are accepted.
 * @param {any} meta
 * @returns {object}
 */
function sanitizeDeviceMetadata(meta) {
  if (!meta || typeof meta !== 'object') return {};

  const num = (v) => (Number.isFinite(Number(v)) ? Number(v) : 0);
  const str = (v, m = 200) => (typeof v === 'string' ? v.slice(0, m) : '');
  const bool = (v) => Boolean(v);

  const screen = meta.screen && typeof meta.screen === 'object' ? meta.screen : {};
  const viewport = meta.viewport && typeof meta.viewport === 'object' ? meta.viewport : {};

  return {
    userAgent: str(meta.userAgent, 500),
    platform: str(meta.platform, 120),
    language: str(meta.language, 60),
    languages: Array.isArray(meta.languages)
      ? meta.languages.filter((l) => typeof l === 'string').slice(0, 10)
      : [],
    timezone: str(meta.timezone, 80),
    screen: {
      width: num(screen.width),
      height: num(screen.height),
      colorDepth: num(screen.colorDepth),
      pixelRatio: num(screen.pixelRatio),
    },
    viewport: {
      width: num(viewport.width),
      height: num(viewport.height),
    },
    hardwareConcurrency: num(meta.hardwareConcurrency),
    deviceMemory: num(meta.deviceMemory),
    touchSupport: bool(meta.touchSupport),
    online: meta.online === undefined ? true : bool(meta.online),
    cookieEnabled: meta.cookieEnabled === undefined ? true : bool(meta.cookieEnabled),
    doNotTrack: str(meta.doNotTrack, 20),
  };
}

// ----------------------------------------------------------------------------
// Hashing helpers
// ----------------------------------------------------------------------------

/**
 * Compute a keyed HMAC-SHA256 of the client IP for abuse detection.
 * Never stores the raw IP. Uses SESSION_SECRET as the key so the hash
 * cannot be reversed by rainbow tables.
 * @param {string} ip
 * @returns {string|null}
 */
function hashIp(ip) {
  if (!ip) return null;
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(ip)).digest('hex');
}

/**
 * Hash a password using scrypt with a fresh random salt.
 * Returns { salt, hash } as hex strings.
 * @param {string} password
 * @returns {{salt: string, hash: string}}
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

/**
 * Verify a password against a stored salt and hash using timing-safe
 * comparison.
 * @param {string} password
 * @param {string} salt
 * @param {string} hash
 * @returns {boolean}
 */
function verifyPassword(password, salt, hash) {
  try {
    const candidate = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(candidate, 'hex');
    const b = Buffer.from(hash, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch (_) {
    return false;
  }
}

/**
 * Timing-safe string comparison.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

// ----------------------------------------------------------------------------
// Express helpers
// ----------------------------------------------------------------------------

/**
 * Wrap an async route handler so that rejected promises flow to the
 * centralized error middleware instead of crashing the process.
 * @param {Function} fn
 * @returns {Function}
 */
const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

/**
 * Application-level error with a code and HTTP status.
 */
class AppError extends Error {
  constructor(message, code = 'ERROR', status = 400) {
    super(message);
    this.code = code;
    this.status = status;
    this.expose = true;
  }
}

/**
 * Send a success response.
 * @param {import('express').Response} res
 * @param {object} [payload={}]
 * @param {number} [status=200]
 */
function ok(res, payload = {}, status = 200) {
  return res.status(status).json({ success: true, ...payload });
}

/**
 * Send an error response.
 * @param {import('express').Response} res
 * @param {string} message
 * @param {string} [code='ERROR']
 * @param {number} [status=400]
 */
function fail(res, message, code = 'ERROR', status = 400) {
  return res.status(status).json({ success: false, message, code });
}

/* ============================================================================
 * SECTION 3 — M-PESA SMS EXTRACTOR
 * ============================================================================
 *
 * Parses pasted text (typically one or more M-Pesa confirmation SMS
 * messages) and extracts:
 *   - The 10-character confirmation code
 *   - The sender's phone number (from the surrounding context)
 *   - The amount (KSH) if present
 *
 * We deliberately avoid hardcoding a single SMS format because Safaricom
 * has several message templates. Instead, we look for:
 *   - Any 10-character alphanumeric token that appears either near the
 *     word "Confirmed" (within ±80 chars) OR at a line boundary.
 *   - The first Kenyan phone number in the surrounding ±180/±260 char
 *     window, excluding the payment destination phone (Pochi).
 *   - The first "Ksh<amount>" match in the same window.
 * ========================================================================== */

// Regex: 10-character uppercase alphanumeric token bounded by word
// boundaries. Global flag so we can iterate.
const MPESA_CODE_RE = /\b([A-Z0-9]{10})\b/g;

// Regex: Kenyan phone in the common formats (2547…, 2541…, 07…, 01…).
// Captures the 9 digits after the country code / leading zero.
const MPESA_PHONE_RE = /(?:\+?254|0)([17]\d{8})/g;

// Regex: "Ksh" followed by a number, optionally with thousands commas.
const MPESA_AMOUNT_RE = /Ksh\s*([\d,]+(?:\.\d{1,2})?)/i;

// Regex: the word "Confirmed" — the marker Safaricom uses in
// successful-transaction SMS messages.
const MPESA_CONFIRMED_RE = /Confirmed/i;

/**
 * Extract M-Pesa entries from a block of pasted text.
 *
 * @param {string} rawText - The pasted SMS content.
 * @param {object} [options]
 * @param {string[]} [options.excludePhones=[]] - Phone numbers to exclude
 *   from sender detection (typically the payment destination).
 * @returns {Array<{code: string, senderPhone: string|null, amount: number|null, raw: string}>}
 */
function extractMpesaEntries(rawText, options = {}) {
  const { excludePhones = [] } = options;

  // Build a set of excluded phone numbers in local 07/01 format.
  const excludeSet = new Set(
    excludePhones.map((p) => {
      const s = String(p || '').replace(/[\s\-().]/g, '');
      if (/^0[17]\d{8}$/.test(s)) return s;
      if (/^254[17]\d{8}$/.test(s)) return '0' + s.slice(3);
      if (/^\+254[17]\d{8}$/.test(s)) return '0' + s.slice(4);
      return s;
    })
  );

  const entries = [];
  if (!rawText) return entries;

  // Normalize line endings so boundary detection is consistent.
  const text = String(rawText).replace(/\r\n?/g, '\n');

  // First pass: locate every 10-char alphanumeric token.
  const codePositions = [];
  let m;
  MPESA_CODE_RE.lastIndex = 0;
  while ((m = MPESA_CODE_RE.exec(text)) !== null) {
    codePositions.push({ code: m[1], index: m.index });
  }

  // Second pass: for each unique code, decide whether it looks like an
  // actual M-Pesa code and extract context.
  const seen = new Set();
  for (const cp of codePositions) {
    if (seen.has(cp.code)) continue;
    seen.add(cp.code);

    // Look for the word "Confirmed" within ±80 chars after the code.
    const afterSlice = text.slice(cp.index + 10, cp.index + 80);
    const beforeSlice = text.slice(Math.max(0, cp.index - 25), cp.index);
    const hasConfirmed =
      MPESA_CONFIRMED_RE.test(afterSlice) || MPESA_CONFIRMED_RE.test(beforeSlice);

    // Or the code sits at a line boundary (typical of SMS screenshots
    // pasted into a textarea).
    const prevChar = cp.index > 0 ? text[cp.index - 1] : '\n';
    const atBoundary =
      prevChar === '\n' || prevChar === ' ' || prevChar === '\t' || cp.index === 0;

    if (!hasConfirmed && !atBoundary) continue;

    // Context window: up to 180 chars before and 260 chars after the code.
    const ctxStart = Math.max(0, cp.index - 180);
    const ctxEnd = Math.min(text.length, cp.index + 10 + 260);
    const context = text.slice(ctxStart, ctxEnd);

    // Extract phone numbers from the context, excluding the payment phone.
    const phones = [];
    let pm;
    MPESA_PHONE_RE.lastIndex = 0;
    while ((pm = MPESA_PHONE_RE.exec(context)) !== null) {
      const p = '0' + pm[1];
      if (!excludeSet.has(p)) phones.push(p);
    }

    // Extract the amount if present.
    let amount = null;
    const am = context.match(MPESA_AMOUNT_RE);
    if (am) amount = parseFloat(am[1].replace(/,/g, ''));

    entries.push({
      code: cp.code,
      senderPhone: phones.length ? phones[0] : null,
      amount,
      raw: context.replace(/\s+/g, ' ').trim().slice(0, 320),
    });
  }

  return entries;
}

/* ============================================================================
 * SECTION 4 — DATABASE CONNECTION
 * ============================================================================
 *
 * Responsibilities:
 *   - Configure Mongoose globally (strictQuery, buffering).
 *   - Connect with retry + exponential backoff (5 attempts).
 *   - Detect replica-set support (for future transaction usage).
 *   - Synchronize indexes for every registered model.
 *   - Provide a graceful disconnect for shutdown.
 * ========================================================================== */

mongoose.set('strictQuery', true);
mongoose.set('bufferCommands', false);

/** Set to true if the connected MongoDB is a replica set (Atlas is). */
let supportsTransactions = false;

/** Options passed to mongoose.connect(). */
const CONNECT_OPTIONS = {
  maxPoolSize: IS_PROD ? 20 : 10,
  serverSelectionTimeoutMS: 15000,
  socketTimeoutMS: 45000,
  connectTimeoutMS: 15000,
  heartbeatFrequencyMS: 10000,
  retryWrites: true,
  appName: 'physics-education-groups',
};

/** Promise-based sleep. */
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/**
 * Connect to MongoDB with retry and exponential backoff.
 * @param {number} [attempt=1]
 * @returns {Promise<boolean>}
 */
async function connectWithRetry(attempt = 1) {
  const MAX = 5;
  try {
    console.log(`[db] Connecting (attempt ${attempt}/${MAX})...`);
    await mongoose.connect(MONGODB_URI, CONNECT_OPTIONS);
    return true;
  } catch (err) {
    console.error(`[db] Attempt ${attempt} failed: ${err.message}`);
    if (attempt >= MAX) throw err;
    const delay = 1500 * Math.pow(2, attempt - 1);
    console.warn(`[db] Retrying in ${Math.round(delay / 1000)}s...`);
    await sleep(delay);
    return connectWithRetry(attempt + 1);
  }
}

/**
 * Probe the connected MongoDB to determine whether it is a replica set.
 * @returns {Promise<boolean>}
 */
async function detectTransactionSupport() {
  try {
    const admin = mongoose.connection.db.admin();
    const info = await admin.command({ hello: 1 }).catch(() => null);
    if (!info) return false;
    return Boolean(info.setName) || info.msg === 'isdbgrid';
  } catch (_) {
    return false;
  }
}

/**
 * Connect to the database and synchronize indexes. Idempotent.
 * @returns {Promise<import('mongoose').Connection>}
 */
async function connectDatabase() {
  if (mongoose.connection.readyState === 1) return mongoose.connection;

  mongoose.connection.on('connected', () => console.log('[db] MongoDB connected.'));
  mongoose.connection.on('disconnected', () => console.warn('[db] MongoDB disconnected.'));
  mongoose.connection.on('reconnected', () => console.log('[db] MongoDB reconnected.'));
  mongoose.connection.on('error', (err) => console.error('[db] Error:', err.message));

  await connectWithRetry();
  supportsTransactions = await detectTransactionSupport();
  console.log(`[db] Transactions: ${supportsTransactions ? 'ENABLED' : 'DISABLED'}`);

  // Build any missing indexes. Safe on every boot.
  for (const name of mongoose.modelNames()) {
    try {
      await mongoose.model(name).syncIndexes();
    } catch (err) {
      console.warn(`[db] Index sync warning for ${name}:`, err.message);
    }
  }
  console.log('[db] Indexes synchronized.');

  return mongoose.connection;
}

/**
 * Close the MongoDB connection gracefully.
 */
async function disconnectDatabase() {
  try {
    if (mongoose.connection.readyState !== 0) {
      await mongoose.connection.close(false);
      console.log('[db] Connection closed.');
    }
  } catch (err) {
    console.error('[db] Close error:', err.message);
  }
}

/* ============================================================================
 * SECTION 5 — MONGOOSE MODELS
 * ============================================================================
 *
 * Collections:
 *   - groups           : Each group's name, normalized name, leader, count.
 *   - members          : Each student's identity + payment + device info.
 *   - admins           : The administrator record (password hashed).
 *   - adminsessions    : Session tokens (admin + member) with TTL.
 *   - settings         : Key/value store for runtime settings.
 *
 * Indexes are declared explicitly so they are documented in one place.
 * ========================================================================== */

// ----------------------------------------------------------------------------
// Group
// ----------------------------------------------------------------------------

const GroupSchema = new mongoose.Schema(
  {
    /**
     * Display name. Preserves the user's original casing and spacing.
     * Required. Max 80 characters.
     */
    name: {
      type: String,
      required: [true, 'Group name is required.'],
      trim: true,
      maxlength: [80, 'Group name too long.'],
    },

    /**
     * Normalized (lowercase, whitespace-collapsed) name used for matching.
     * Unique — prevents duplicates like "Group A" and "group  a".
     */
    normalizedName: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
    },

    /**
     * Reference to the current group leader (a Member document).
     * Null until the first member joins.
     */
    leader: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Member',
      default: null,
    },

    /**
     * Denormalized member count. Kept in sync with the members collection.
     * The real cap is enforced atomically at registration time using the
     * current value of Settings.max_group_members.
     */
    memberCount: {
      type: Number,
      default: 0,
      min: 0,
      max: [
        CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT,
        `Group cannot exceed ${CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT} members.`,
      ],
    },
  },
  { timestamps: true, versionKey: false }
);

GroupSchema.virtual('isFull').get(function () {
  return this.memberCount >= CONFIG.MAX_GROUP_MEMBERS_DEFAULT;
});
GroupSchema.virtual('availableSlots').get(function () {
  return Math.max(0, CONFIG.MAX_GROUP_MEMBERS_DEFAULT - this.memberCount);
});
GroupSchema.set('toJSON', { virtuals: true });
GroupSchema.set('toObject', { virtuals: true });

const Group = mongoose.model('Group', GroupSchema);

// ----------------------------------------------------------------------------
// Member
// ----------------------------------------------------------------------------

const DeviceMetadataSchema = new mongoose.Schema(
  {
    userAgent: { type: String, default: '', maxlength: 500 },
    platform: { type: String, default: '', maxlength: 120 },
    language: { type: String, default: '', maxlength: 60 },
    languages: { type: [String], default: [] },
    timezone: { type: String, default: '', maxlength: 80 },
    screen: {
      width: { type: Number, default: 0 },
      height: { type: Number, default: 0 },
      colorDepth: { type: Number, default: 0 },
      pixelRatio: { type: Number, default: 0 },
    },
    viewport: {
      width: { type: Number, default: 0 },
      height: { type: Number, default: 0 },
    },
    hardwareConcurrency: { type: Number, default: 0 },
    deviceMemory: { type: Number, default: 0 },
    touchSupport: { type: Boolean, default: false },
    online: { type: Boolean, default: true },
    cookieEnabled: { type: Boolean, default: true },
    doNotTrack: { type: String, default: '', maxlength: 20 },
  },
  { _id: false }
);

const MemberSchema = new mongoose.Schema(
  {
    /**
     * Unique registration number across the entire system.
     * Always stored uppercase. Unique index.
     */
    regNo: {
      type: String,
      required: [true, 'Registration number is required.'],
      unique: true,
      index: true,
      trim: true,
      uppercase: true,
      minlength: [3, 'Registration number too short.'],
      maxlength: [40, 'Registration number too long.'],
    },

    /** Full name (2–120 chars). */
    name: {
      type: String,
      required: [true, 'Full name is required.'],
      trim: true,
      minlength: [2, 'Full name too short.'],
      maxlength: [120, 'Full name too long.'],
    },

    /** Phone number in E.164 form (e.g. +254712345678). */
    phone: {
      type: String,
      required: [true, 'Phone number is required.'],
      trim: true,
      maxlength: [20, 'Phone number too long.'],
    },

    /** Reference to the Group this member belongs to. */
    group: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Group',
      required: true,
      index: true,
    },

    /** True for exactly one member per group (the leader). */
    isLeader: {
      type: Boolean,
      default: false,
      index: true,
    },

    /**
     * Browser-generated fingerprint. Unique sparse index prevents a
     * single browser from submitting more than one registration.
     */
    deviceId: {
      type: String,
      default: null,
      trim: true,
      maxlength: 128,
    },

    /** Non-sensitive device metadata. */
    deviceMetadata: {
      type: DeviceMetadataSchema,
      default: () => ({}),
    },

    /** Optional HMAC-SHA256 of the client IP. Never a raw IP. */
    ipHash: {
      type: String,
      default: null,
      select: false,
    },

    // -------- Lab Manual Payment fields (all optional) --------

    /** M-Pesa confirmation code (10 chars, uppercase). */
    mpesaCode: {
      type: String,
      default: null,
      trim: true,
      uppercase: true,
      maxlength: 20,
    },

    /** Amount paid (KSH). */
    paymentAmount: {
      type: Number,
      default: null,
      min: 0,
    },

    /** Free-text note (time & day the student paid). */
    paymentNote: {
      type: String,
      default: null,
      trim: true,
      maxlength: 200,
    },

    /** When the student submitted the code. */
    paymentSubmittedAt: {
      type: Date,
      default: null,
    },

    /**
     * Admin-managed verification state:
     *   null      — no code submitted (payment not required)
     *   'pending' — code submitted, awaiting admin check
     *   'verified' — admin confirmed on their M-Pesa statement
     *   'rejected' — admin rejected the code
     */
    paymentStatus: {
      type: String,
      enum: ['pending', 'verified', 'rejected', null],
      default: null,
      index: true,
    },

    paymentVerifiedAt: { type: Date, default: null },
    paymentVerifiedBy: { type: String, default: null, maxlength: 500 },
    paymentRejectedReason: { type: String, default: null, maxlength: 200 },
  },
  { timestamps: true, versionKey: false }
);

// Unique sparse index on deviceId — only enforced for non-null string IDs.
MemberSchema.index(
  { deviceId: 1 },
  {
    unique: true,
    sparse: true,
    partialFilterExpression: { deviceId: { $type: 'string' } },
    name: 'uniq_deviceId_when_set',
  }
);

// Compound index for listing a group's members in order.
MemberSchema.index({ group: 1, createdAt: 1 });
MemberSchema.index({ group: 1, isLeader: -1, createdAt: 1 });

// Unique sparse index on mpesaCode — only enforced for non-null strings.
// Prevents two students from submitting the same code.
MemberSchema.index(
  { mpesaCode: 1 },
  {
    unique: true,
    partialFilterExpression: { mpesaCode: { $type: 'string' } },
    name: 'uniq_mpesaCode_when_set',
  }
);

const Member = mongoose.model('Member', MemberSchema);

// ----------------------------------------------------------------------------
// Admin
// ----------------------------------------------------------------------------

const AdminSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      index: true,
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 60,
    },

    /** scrypt hash (hex, 64 bytes). */
    passwordHash: { type: String, required: true, select: false },

    /** Random hex salt for the hash. */
    passwordSalt: { type: String, required: true, select: false },

    lastLoginAt: { type: Date, default: null },
    loginCount: { type: Number, default: 0, min: 0 },
  },
  { timestamps: true, versionKey: false }
);

const Admin = mongoose.model('Admin', AdminSchema);

// ----------------------------------------------------------------------------
// AdminSession (used for both admin and member sessions)
// ----------------------------------------------------------------------------

const AdminSessionSchema = new mongoose.Schema(
  {
    /** 96-char random hex token. Unique index. */
    token: {
      type: String,
      required: true,
      unique: true,
      index: true,
      minlength: 32,
      maxlength: 200,
    },

    /** Session kind: 'admin' or 'member'. */
    role: {
      type: String,
      required: true,
      enum: ['admin', 'member'],
      index: true,
    },

    /** Member ID when role === 'member'; null otherwise. */
    subjectId: { type: mongoose.Schema.Types.ObjectId, default: null },

    /** Group ID when role === 'member'; null otherwise. */
    group: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', default: null },

    /** Truncated UA for diagnostics. */
    userAgent: { type: String, default: '', maxlength: 300 },

    /** TTL index — MongoDB deletes expired sessions automatically. */
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 },
    },
  },
  { timestamps: true, versionKey: false }
);

const AdminSession = mongoose.model('AdminSession', AdminSessionSchema);

// ----------------------------------------------------------------------------
// Settings (key/value store)
// ----------------------------------------------------------------------------

const SettingsSchema = new mongoose.Schema(
  {
    key: { type: String, required: true, unique: true, index: true, trim: true },
    value: { type: mongoose.Schema.Types.Mixed, default: null },
  },
  { timestamps: true, versionKey: false }
);

const Settings = mongoose.model('Settings', SettingsSchema);

/* ============================================================================
 * SECTION 6 — SETTINGS & BUSINESS HELPERS
 * ============================================================================
 *
 * Thin wrappers around the Settings collection and shared business logic
 * (leader reconciliation, member count recalculation, response shaping).
 * ========================================================================== */

/**
 * Read a setting by key, returning the default when not set.
 * @param {string} key
 * @param {any} [defaultValue=null]
 * @returns {Promise<any>}
 */
async function getSetting(key, defaultValue = null) {
  try {
    const doc = await Settings.findOne({ key }).lean();
    return doc ? doc.value : defaultValue;
  } catch (_) {
    return defaultValue;
  }
}

/**
 * Upsert a setting.
 * @param {string} key
 * @param {any} value
 * @returns {Promise<any>}
 */
async function setSetting(key, value) {
  const doc = await Settings.findOneAndUpdate(
    { key },
    { key, value },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  ).lean();
  return doc ? doc.value : value;
}

/**
 * Is registration currently open?
 * @returns {Promise<boolean>}
 */
async function isRegistrationOpen() {
  const v = await getSetting('registration_open', true);
  return v !== false;
}

/**
 * Is M-Pesa payment proof required on registration?
 * @returns {Promise<boolean>}
 */
async function isPaymentProofRequired() {
  const v = await getSetting('require_payment_proof', false);
  return v === true;
}

/**
 * The configured lab-manual fee (KSH).
 * @returns {Promise<number>}
 */
async function getPaymentAmount() {
  const v = await getSetting('payment_amount', 45);
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : 45;
}

/**
 * The configured Pochi phone (display form, e.g. 0741742291).
 * @returns {Promise<string>}
 */
async function getPaymentPhone() {
  const v = await getSetting('payment_phone', '0741742291');
  const s = String(v || '').trim();
  return s || '0741742291';
}

/**
 * The configured max members per group.
 * Clamped between 1 and MAX_GROUP_MEMBERS_HARD_LIMIT.
 * @returns {Promise<number>}
 */
async function getMaxGroupMembers() {
  const v = await getSetting('max_group_members', CONFIG.MAX_GROUP_MEMBERS_DEFAULT);
  const n = Number(v);
  if (!Number.isFinite(n)) return CONFIG.MAX_GROUP_MEMBERS_DEFAULT;
  return Math.max(1, Math.min(CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT, Math.floor(n)));
}

/**
 * Ensure a group has exactly one leader if it has any members.
 * - Promotes the earliest member when no leader exists.
 * - Demotes any other member flagged isLeader.
 * @param {string|import('mongoose').Types.ObjectId} groupId
 * @returns {Promise<object|null>}
 */
async function reconcileGroupLeader(groupId) {
  const group = await Group.findById(groupId);
  if (!group) return null;

  const members = await Member.find({ group: groupId }).sort({ createdAt: 1, _id: 1 });

  // Empty group: leader should be null.
  if (members.length === 0) {
    if (group.leader) {
      group.leader = null;
      await group.save();
    }
    return group;
  }

  // Determine the leader. If the stored leader is no longer a member,
  // promote the earliest remaining member.
  let leaderId = group.leader;
  const leaderStillPresent = leaderId && members.some((m) => String(m._id) === String(leaderId));
  if (!leaderStillPresent) {
    leaderId = members[0]._id;
    group.leader = leaderId;
    await group.save();
  }

  // Flip isLeader flags so exactly one member has isLeader: true.
  const leaderMember = members.find((m) => String(m._id) === String(leaderId));
  if (leaderMember && !leaderMember.isLeader) {
    await Member.updateOne({ _id: leaderMember._id }, { $set: { isLeader: true } });
  }
  await Member.updateMany(
    { group: groupId, _id: { $ne: leaderId }, isLeader: true },
    { $set: { isLeader: false } }
  );

  return group;
}

/**
 * Recompute a group's memberCount from the members collection.
 * @param {string|import('mongoose').Types.ObjectId} groupId
 * @returns {Promise<number>}
 */
async function recalcMemberCount(groupId) {
  const count = await Member.countDocuments({ group: groupId });
  await Group.updateOne({ _id: groupId }, { $set: { memberCount: count } });
  return count;
}

/**
 * Shape a Group document into the JSON returned to clients.
 * @param {object} group
 * @param {object} [extra={}]
 * @returns {object}
 */
function shapeGroup(group, extra = {}) {
  return {
    id: String(group._id),
    name: group.name,
    normalizedName: group.normalizedName,
    memberCount: group.memberCount,
    capacity: extra.capacity != null ? extra.capacity : CONFIG.MAX_GROUP_MEMBERS_DEFAULT,
    leader: group.leader ? String(group.leader) : null,
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
    ...extra,
  };
}

/**
 * Shape a Member document into the JSON returned to clients.
 * @param {object} member
 * @param {object} [opts]
 * @param {boolean} [opts.includePayment=false] - Include payment fields.
 * @returns {object}
 */
function shapeMember(member, opts = {}) {
  const base = {
    id: String(member._id),
    regNo: member.regNo,
    name: member.name,
    phone: member.phone,
    isLeader: Boolean(member.isLeader),
    role: member.isLeader ? 'GROUP LEADER' : 'MEMBER',
    groupId: String(member.group),
    createdAt: member.createdAt,
    updatedAt: member.updatedAt,
  };

  if (opts.includePayment) {
    base.mpesaCode = member.mpesaCode || null;
    base.paymentAmount = member.paymentAmount != null ? member.paymentAmount : null;
    base.paymentNote = member.paymentNote || null;
    base.paymentSubmittedAt = member.paymentSubmittedAt || null;
    base.paymentStatus = member.paymentStatus || null;
    base.paymentVerifiedAt = member.paymentVerifiedAt || null;
    base.paymentRejectedReason = member.paymentRejectedReason || null;
  }

  return base;
}

/* ============================================================================
 * SECTION 7 — SERVER-SENT EVENTS (SSE)
 * ============================================================================
 *
 * Admin dashboard subscribes to /api/admin/events. Whenever a
 * registration, member change, group change, or settings change occurs,
 * we broadcast an SSE event to every connected admin browser.
 *
 * We also send a heartbeat comment every 25 seconds to keep proxies and
 * Render's load balancer from closing the connection.
 * ========================================================================== */

/** Set of active SSE response objects. */
const sseClients = new Set();

/**
 * Broadcast an event to every connected SSE client.
 * @param {string} event
 * @param {any} data
 */
function sseBroadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of sseClients) {
    try {
      res.write(payload);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}

// Heartbeat every 25 seconds. `.unref()` so the timer doesn't keep the
// process alive during graceful shutdown.
setInterval(() => {
  for (const res of sseClients) {
    try {
      res.write(`: ping ${Date.now()}\n\n`);
    } catch (_) {
      sseClients.delete(res);
    }
  }
}, 25000).unref();

/* ============================================================================
 * SECTION 8 — EXPRESS APP & MIDDLEWARE
 * ============================================================================
 *
 * The order of `app.use()` calls matters:
 *   1. trust proxy  — required on Render for HTTPS detection.
 *   2. helmet       — sets security headers.
 *   3. cors         — handles cross-origin requests.
 *   4. body parsers — JSON and form-urlencoded.
 *   5. cookieParser — needed for session cookies.
 *   6. rate limit   — /api/* only.
 *   7. CSRF         — /api/* non-GET only.
 *   8. auth         — attached per-route.
 * ========================================================================== */

const app = express();

// Required on Render, which terminates TLS in front of the app.
app.set('trust proxy', 1);

// ----------------------------------------------------------------------------
// Helmet — security headers
// ----------------------------------------------------------------------------
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"], // inline <style> allowed
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        // Only enforce HTTPS upgrades in production.
        upgradeInsecureRequests: IS_PROD ? [] : null,
      },
    },
    crossOriginEmbedderPolicy: false,
    hsts: IS_PROD
      ? { maxAge: 15552000, includeSubDomains: true, preload: false }
      : false,
    referrerPolicy: { policy: 'no-referrer' },
  })
);

// ----------------------------------------------------------------------------
// CORS
// ----------------------------------------------------------------------------
app.use(
  cors({
    origin(origin, cb) {
      // Same-origin requests have no Origin header; allow them.
      if (!origin) return cb(null, true);
      // Empty allow-list means same-origin only.
      if (CORS_ORIGIN.length === 0) return cb(null, false);
      return cb(null, CORS_ORIGIN.includes(origin));
    },
    credentials: true,
  })
);

// ----------------------------------------------------------------------------
// Body parsing
// ----------------------------------------------------------------------------
app.use(express.json({ limit: '256kb' }));
app.use(express.urlencoded({ extended: false, limit: '256kb' }));
app.use(cookieParser());

// ----------------------------------------------------------------------------
// Rate limiters
// ----------------------------------------------------------------------------

/** General limiter applied to every /api/* route. */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 400,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please slow down.', code: 'RATE_LIMIT' },
});

/** Tighter limiter for the register endpoint. */
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many registration attempts. Try again later.', code: 'RATE_LIMIT' },
});

/** Tighter limiter for login endpoints. */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 25,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many login attempts. Try again later.', code: 'RATE_LIMIT' },
});

app.use('/api/', generalLimiter);

// ----------------------------------------------------------------------------
// CSRF — double-submit cookie
// ----------------------------------------------------------------------------
//
// GET/HEAD/OPTIONS are exempt. Mutating methods must echo the CSRF token
// from the peg_csrf cookie in the X-CSRF-Token header.

/**
 * CSRF middleware.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 */
function requireCsrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  const cookieToken = req.cookies ? req.cookies[CONFIG.CSRF_COOKIE] : null;
  const headerToken = req.get(CONFIG.CSRF_HEADER);

  if (!cookieToken || !headerToken || !safeEqual(cookieToken, headerToken)) {
    return fail(res, 'Invalid or missing CSRF token.', 'CSRF_INVALID', 403);
  }
  return next();
}

app.use('/api/', requireCsrf);

// ----------------------------------------------------------------------------
// Cookie helper
// ----------------------------------------------------------------------------

/**
 * Build cookie options with a given max-age.
 * @param {number} maxAgeMs
 * @returns {object}
 */
const cookieOpts = (maxAgeMs) => ({
  httpOnly: true,
  secure: CONFIG.COOKIE_SECURE,
  sameSite: CONFIG.COOKIE_SAME_SITE,
  maxAge: maxAgeMs,
  path: '/',
});

// ----------------------------------------------------------------------------
// Session attach + auth middlewares
// ----------------------------------------------------------------------------

/**
 * Load a session from a cookie and attach it to req._session.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {Function} next
 * @param {string} cookieName
 * @param {'admin'|'member'} role
 */
async function attachSession(req, res, next, cookieName, role) {
  try {
    const token = req.cookies ? req.cookies[cookieName] : null;
    if (!token) return next();

    const session = await AdminSession.findOne({
      token,
      role,
      expiresAt: { $gt: new Date() },
    }).lean();

    if (!session) return next();
    req._session = session;
    return next();
  } catch (err) {
    return next(err);
  }
}

/** Require a valid admin session. */
function requireAdmin(req, res, next) {
  attachSession(
    req,
    res,
    () => {
      if (!req._session || req._session.role !== 'admin') {
        return fail(res, 'Administrator authentication required.', 'AUTH_REQUIRED', 401);
      }
      return next();
    },
    CONFIG.ADMIN_COOKIE,
    'admin'
  );
}

/** Require a valid member session. */
function requireMember(req, res, next) {
  attachSession(
    req,
    res,
    () => {
      if (!req._session || req._session.role !== 'member') {
        return fail(res, 'Member authentication required.', 'AUTH_REQUIRED', 401);
      }
      return next();
    },
    CONFIG.MEMBER_COOKIE,
    'member'
  );
}

/* ============================================================================
 * SECTION 9 — PUBLIC ROUTES
 * ============================================================================
 *
 * - /api/health              : liveness probe
 * - /api/csrf-token          : issue a CSRF token
 * - /api/registration-status : is registration open?
 * - /api/payment-config      : public payment + capacity config
 * - /api/register            : student registration
 * ========================================================================== */

/**
 * Liveness probe.
 * Returns app status, uptime, DB state, and version.
 */
app.get('/api/health', (req, res) => {
  const states = ['disconnected', 'connected', 'connecting', 'disconnecting'];
  return ok(res, {
    status: 'ok',
    uptime: Math.floor(process.uptime()),
    db: states[mongoose.connection.readyState] || 'unknown',
    transactions: supportsTransactions,
    version: '1.5.0',
  });
});

/**
 * Issue a fresh CSRF token.
 * The token is set as a readable cookie and also returned in the body.
 * The client echoes it in the X-CSRF-Token header on mutating requests.
 */
app.get('/api/csrf-token', (req, res) => {
  const token = crypto.randomBytes(24).toString('hex');
  res.cookie(CONFIG.CSRF_COOKIE, token, {
    httpOnly: false,
    secure: CONFIG.COOKIE_SECURE,
    sameSite: CONFIG.COOKIE_SAME_SITE,
    maxAge: CONFIG.CSRF_TTL_MS,
    path: '/',
  });
  return ok(res, { token });
});

/**
 * Public: is registration currently open?
 */
app.get(
  '/api/registration-status',
  asyncHandler(async (req, res) => {
    const open = await isRegistrationOpen();
    return ok(res, { open });
  })
);

/**
 * Public: exposes payment + capacity configuration to the register page.
 * The register page uses requirePaymentProof to decide whether to
 * reveal the M-Pesa code and payment note fields.
 */
app.get(
  '/api/payment-config',
  asyncHandler(async (req, res) => {
    const [registrationOpen, requirePaymentProof, paymentAmount, paymentPhone, maxGroupMembers] =
      await Promise.all([
        isRegistrationOpen(),
        isPaymentProofRequired(),
        getPaymentAmount(),
        getPaymentPhone(),
        getMaxGroupMembers(),
      ]);
    return ok(res, {
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    });
  })
);

/**
 * POST /api/register
 *
 * Body:
 *   regNo          — required
 *   name           — required
 *   phone          — required
 *   groupName      — required
 *   deviceId       — required
 *   deviceMetadata — required (object)
 *   mpesaCode      — required only if payment proof is ON
 *   paymentNote    — required only if payment proof is ON
 *
 * Response 201 on success with member + group + payment info.
 * Every error uses the standard { success: false, message, code } shape.
 */
app.post(
  '/api/register',
  registerLimiter,
  asyncHandler(async (req, res) => {
    // -------- Read current settings --------
    const [
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
    ] = await Promise.all([
      isRegistrationOpen(),
      isPaymentProofRequired(),
      getPaymentAmount(),
      getPaymentPhone(),
      getMaxGroupMembers(),
    ]);

    if (!registrationOpen) {
      return fail(
        res,
        'Registration is currently closed. Please check back later or contact the Administrator.',
        'REGISTRATION_CLOSED',
        403
      );
    }

    // -------- Parse + normalize input --------
    const body = req.body || {};
    const regNo = normalizeRegNo(body.regNo);
    const name = normalizeName(body.name);
    const phoneRaw = body.phone;
    const groupDisplay = displayGroupName(body.groupName);
    const groupNorm = normalizeGroupName(body.groupName);
    const deviceId = typeof body.deviceId === 'string' ? body.deviceId.trim() : '';
    const deviceMetadata = sanitizeDeviceMetadata(body.deviceMetadata);
    const mpesaCode = normalizeMpesaCode(body.mpesaCode);
    const paymentNote = sanitizePaymentNote(body.paymentNote);

    // -------- Field validation --------
    if (!isValidRegNo(regNo)) return fail(res, 'Please provide a valid registration number.', 'INVALID_REQNO', 400);
    if (!isValidName(name)) return fail(res, 'Please provide a valid full name.', 'INVALID_NAME', 400);

    const phone = normalizePhone(phoneRaw);
    if (!phone) return fail(res, 'Please provide a valid Kenyan phone number.', 'INVALID_PHONE', 400);

    if (!isValidGroupName(groupNorm)) return fail(res, 'Please provide a valid group name.', 'INVALID_GROUP', 400);
    if (!isValidDeviceId(deviceId)) return fail(res, 'Unable to identify this device. Please refresh and try again.', 'INVALID_DEVICE', 400);

    // -------- Payment proof (only when enabled) --------
    if (requirePaymentProof) {
      if (!mpesaCode) {
        return fail(
          res,
          `Payment proof is required. Please send KSH ${paymentAmount} to ${paymentPhone} and paste the 10-character M-Pesa confirmation code.`,
          'PAYMENT_REQUIRED',
          400
        );
      }
      const codeCheck = validateMpesaCodeHard(mpesaCode);
      if (!codeCheck.valid) {
        return fail(res, codeCheck.reason, 'INVALID_MPESA_CODE', 400);
      }
      if (!paymentNote) {
        return fail(res, 'Please note down the time and day you paid in the payment note field.', 'PAYMENT_NOTE_REQUIRED', 400);
      }
      const existingCode = await Member.findOne({ mpesaCode }).lean();
      if (existingCode) {
        return fail(
          res,
          'This M-Pesa code has already been submitted by another member. Each code can only be used once.',
          'DUPLICATE_MPESA_CODE',
          409
        );
      }
    }

    // -------- Duplicate REG number --------
    const existingReg = await Member.findOne({ regNo }).lean();
    if (existingReg) {
      console.log(`[register] rejected duplicate regNo=${regNo}`);
      return fail(
        res,
        'This registration number has already been registered. If you believe this is an error, please contact the Administrator.',
        'DUPLICATE_REGNO',
        409
      );
    }

    // -------- Device lock --------
    if (ENFORCE_DEVICE_LOCK) {
      const existingDevice = await Member.findOne({ deviceId }).lean();
      if (existingDevice) {
        console.log('[register] rejected duplicate device');
        return fail(
          res,
          'This device has already been used to submit registration details. If you believe this is an error, please contact the Administrator.',
          'DEVICE_USED',
          409
        );
      }
    }

    // -------- Find or create the group (case/whitespace normalized) --------
    let group = await Group.findOne({ normalizedName: groupNorm });
    let isNewGroup = false;

    if (!group) {
      try {
        group = await Group.create({
          name: groupDisplay,
          normalizedName: groupNorm,
          memberCount: 0,
        });
        isNewGroup = true;
        console.log(`[register] created group "${groupDisplay}"`);
      } catch (err) {
        // Another concurrent request may have created it first.
        if (err && err.code === 11000) {
          group = await Group.findOne({ normalizedName: groupNorm });
        } else {
          throw err;
        }
      }
    }

    if (!group) {
      return fail(res, 'We could not complete your registration. Please contact the Administrator.', 'GROUP_CREATE_FAILED', 500);
    }

    // -------- Atomic capacity increment --------
    // This is the final authority on group size. `$lt: maxGroupMembers`
    // means the update only matches if the current count is below the cap.
    // MongoDB guarantees per-document atomicity, so two simultaneous
    // registrations cannot both succeed for the last slot.
    const incremented = await Group.findOneAndUpdate(
      { _id: group._id, memberCount: { $lt: maxGroupMembers } },
      { $inc: { memberCount: 1 } },
      { new: true }
    );

    if (!incremented) {
      console.log(`[register] group full: ${group.normalizedName} (cap=${maxGroupMembers})`);
      return fail(
        res,
        `This group is already full. A group can have a maximum of ${maxGroupMembers} members. Please contact the Administrator or choose another group.`,
        'GROUP_FULL',
        409
      );
    }

    // First member of a group becomes the leader.
    const isLeader = incremented.memberCount === 1;

    // -------- Create the member (roll back capacity on failure) --------
    let member;
    try {
      member = await Member.create({
        regNo,
        name,
        phone,
        group: group._id,
        isLeader,
        deviceId: deviceId || null,
        deviceMetadata,
        ipHash: STORE_IP_HASH ? hashIp(req.ip) : null,
        mpesaCode: mpesaCode || null,
        paymentAmount: mpesaCode ? paymentAmount : null,
        paymentNote: paymentNote || null,
        paymentSubmittedAt: mpesaCode ? new Date() : null,
        paymentStatus: mpesaCode ? 'pending' : null,
      });
    } catch (err) {
      // Undo the capacity increment.
      await Group.updateOne({ _id: group._id }, { $inc: { memberCount: -1 } });

      if (err && err.code === 11000) {
        const keys = err.keyPattern || {};
        if (keys.regNo) {
          return fail(res, 'This registration number has already been registered. If you believe this is an error, please contact the Administrator.', 'DUPLICATE_REGNO', 409);
        }
        if (keys.deviceId) {
          return fail(res, 'This device has already been used to submit registration details. If you believe this is an error, please contact the Administrator.', 'DEVICE_USED', 409);
        }
        if (keys.mpesaCode) {
          return fail(res, 'This M-Pesa code has already been submitted by another member. Each code can only be used once.', 'DUPLICATE_MPESA_CODE', 409);
        }
      }
      throw err;
    }

    // -------- Leader assignment --------
    if (isLeader) {
      await Group.updateOne({ _id: group._id, leader: null }, { $set: { leader: member._id } });
      await reconcileGroupLeader(group._id);
      console.log(`[register] leader assigned: ${regNo} → ${group.normalizedName}`);
    }

    // -------- Recompute count defensively --------
    const freshCount = await recalcMemberCount(group._id);
    const finalGroup = await Group.findById(group._id);

    // -------- Notify admins --------
    sseBroadcast('registration', {
      member: shapeMember(member, { includePayment: true }),
      group: shapeGroup(finalGroup, { capacity: maxGroupMembers }),
      isNewGroup,
      isLeader,
    });

    console.log(
      `[register] success regNo=${regNo} group=${group.normalizedName} leader=${isLeader} paid=${Boolean(mpesaCode)}`
    );

    const message = isLeader
      ? 'You are the first member to register for this group. You have been assigned as the Group Leader.'
      : 'Registration successful.';

    return ok(
      res,
      {
        message,
        isLeader,
        isNewGroup,
        member: shapeMember(member, { includePayment: true }),
        group: shapeGroup(finalGroup, { capacity: maxGroupMembers, memberCount: freshCount }),
        payment: {
          requirePaymentProof,
          paymentAmount,
          paymentPhone,
          mpesaCode: member.mpesaCode || null,
          paymentNote: member.paymentNote || null,
          paymentSubmittedAt: member.paymentSubmittedAt || null,
          paymentStatus: member.paymentStatus || null,
        },
      },
      201
    );
  })
);

/* ============================================================================
 * SECTION 10 — MEMBER ROUTES
 * ============================================================================
 *
 * - POST /api/member/login   : group name + reg no → session cookie
 * - POST /api/member/logout  : clears session
 * - GET  /api/member/me      : current member profile
 * - GET  /api/member/group   : member's own group + all its members
 * ========================================================================== */

app.post(
  '/api/member/login',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const groupNorm = normalizeGroupName(req.body.groupName);
    const regNo = normalizeRegNo(req.body.regNo);

    if (!groupNorm || !regNo) {
      return fail(res, 'Group name and registration number are required.', 'VALIDATION', 400);
    }

    const group = await Group.findOne({ normalizedName: groupNorm });
    if (!group) {
      return fail(res, 'Invalid group name or registration number.', 'INVALID_CREDENTIALS', 401);
    }

    const member = await Member.findOne({ regNo, group: group._id });
    if (!member) {
      return fail(res, 'Invalid group name or registration number.', 'INVALID_CREDENTIALS', 401);
    }

    const token = crypto.randomBytes(48).toString('hex');
    await AdminSession.create({
      token,
      role: 'member',
      subjectId: member._id,
      group: group._id,
      userAgent: String(req.get('user-agent') || '').slice(0, 300),
      expiresAt: new Date(Date.now() + CONFIG.MEMBER_SESSION_TTL_MS),
    });

    res.cookie(CONFIG.MEMBER_COOKIE, token, cookieOpts(CONFIG.MEMBER_SESSION_TTL_MS));

    console.log(`[member-login] ${regNo} → ${group.normalizedName}`);

    const maxGroupMembers = await getMaxGroupMembers();

    return ok(res, {
      message: 'Login successful.',
      member: shapeMember(member, { includePayment: true }),
      group: shapeGroup(group, { capacity: maxGroupMembers }),
    });
  })
);

app.post(
  '/api/member/logout',
  asyncHandler(async (req, res) => {
    const token = req.cookies ? req.cookies[CONFIG.MEMBER_COOKIE] : null;
    if (token) await AdminSession.deleteOne({ token, role: 'member' });
    res.clearCookie(CONFIG.MEMBER_COOKIE, { path: '/' });
    return ok(res, { message: 'Logged out.' });
  })
);

app.get(
  '/api/member/me',
  requireMember,
  asyncHandler(async (req, res) => {
    const member = await Member.findById(req._session.subjectId);
    if (!member) return fail(res, 'Session invalid.', 'SESSION_INVALID', 401);

    const group = await Group.findById(member.group);
    const maxGroupMembers = await getMaxGroupMembers();

    return ok(res, {
      member: shapeMember(member, { includePayment: true }),
      group: group ? shapeGroup(group, { capacity: maxGroupMembers }) : null,
    });
  })
);

app.get(
  '/api/member/group',
  requireMember,
  asyncHandler(async (req, res) => {
    const member = await Member.findById(req._session.subjectId);
    if (!member) return fail(res, 'Session invalid.', 'SESSION_INVALID', 401);

    const group = await Group.findById(member.group);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const [members, maxGroupMembers, requirePaymentProof, paymentAmount, paymentPhone] =
      await Promise.all([
        Member.find({ group: group._id })
          .sort({ isLeader: -1, createdAt: 1 })
          .select('regNo name phone isLeader group createdAt')
          .lean(),
        getMaxGroupMembers(),
        isPaymentProofRequired(),
        getPaymentAmount(),
        getPaymentPhone(),
      ]);

    const leader = members.find((m) => m.isLeader) || null;

    return ok(res, {
      group: {
        ...shapeGroup(group, { capacity: maxGroupMembers }),
        leaderName: leader ? leader.name : null,
        leaderRegNo: leader ? leader.regNo : null,
      },
      members: members.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        isLeader: Boolean(m.isLeader),
        role: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
        createdAt: m.createdAt,
      })),
      viewer: {
        regNo: member.regNo,
        name: member.name,
        isLeader: member.isLeader,
        mpesaCode: member.mpesaCode || null,
        paymentNote: member.paymentNote || null,
        paymentAmount: member.paymentAmount != null ? member.paymentAmount : null,
        paymentSubmittedAt: member.paymentSubmittedAt || null,
        paymentStatus: member.paymentStatus || null,
      },
      paymentConfig: { requirePaymentProof, paymentAmount, paymentPhone },
    });
  })
);

/* ============================================================================
 * SECTION 11 — ADMIN ROUTES
 * ============================================================================
 *
 * - POST /api/admin/login                        : admin login
 * - POST /api/admin/logout                       : clears admin session
 * - GET  /api/admin/me                           : current admin check
 * - GET  /api/admin/registration-status          : is registration open?
 * - POST /api/admin/registration-toggle          : toggle open/closed
 * - GET  /api/admin/settings                     : read all settings
 * - POST /api/admin/settings                     : update settings
 * - GET  /api/admin/paid-summary                 : counts
 * - POST /api/admin/verify-payments              : paste & verify
 * - GET  /api/admin/pending-payments             : list pending
 * - POST /api/admin/members/:id/verify-payment   : manual verify
 * - POST /api/admin/members/:id/reject-payment   : manual reject
 * - GET  /api/admin/dashboard                    : totals + groups + recent
 * - GET  /api/admin/groups                       : list groups
 * - GET  /api/admin/groups/:id                   : group + members
 * - POST /api/admin/groups                       : create group
 * - PATCH /api/admin/groups/:id                  : rename group
 * - DELETE /api/admin/groups/:id                 : delete group
 * - POST /api/admin/members                      : add member
 * - PATCH /api/admin/members/:id                 : edit member
 * - DELETE /api/admin/members/:id                : delete member
 * ========================================================================== */

// ----------------------------------------------------------------------------
// Admin login
// ----------------------------------------------------------------------------

app.post(
  '/api/admin/login',
  loginLimiter,
  asyncHandler(async (req, res) => {
    const username = String(req.body.username || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!username || !password) {
      return fail(res, 'Username and password are required.', 'VALIDATION', 400);
    }

    let admin = await Admin.findOne({ username }).select('+passwordHash +passwordSalt');

    if (!admin) {
      // Bootstrap: only env-defined credentials can create the admin.
      if (username !== ADMIN_USERNAME.toLowerCase() || !safeEqual(password, ADMIN_PASSWORD)) {
        console.warn(`[admin-login] rejected unknown user "${username}"`);
        return fail(res, 'Invalid administrator credentials.', 'INVALID_CREDENTIALS', 401);
      }

      const { salt, hash } = hashPassword(ADMIN_PASSWORD);
      admin = await Admin.create({ username, passwordHash: hash, passwordSalt: salt });
      admin = await Admin.findOne({ username }).select('+passwordHash +passwordSalt');
      console.log('[admin-login] bootstrap admin created.');
    } else {
      const valid = verifyPassword(password, admin.passwordSalt, admin.passwordHash);
      if (!valid) {
        console.warn(`[admin-login] bad password for "${username}"`);
        return fail(res, 'Invalid administrator credentials.', 'INVALID_CREDENTIALS', 401);
      }
    }

    await Admin.updateOne(
      { _id: admin._id },
      { $set: { lastLoginAt: new Date() }, $inc: { loginCount: 1 } }
    );

    const token = crypto.randomBytes(48).toString('hex');
    await AdminSession.create({
      token,
      role: 'admin',
      userAgent: String(req.get('user-agent') || '').slice(0, 300),
      expiresAt: new Date(Date.now() + CONFIG.ADMIN_SESSION_TTL_MS),
    });

    res.cookie(CONFIG.ADMIN_COOKIE, token, cookieOpts(CONFIG.ADMIN_SESSION_TTL_MS));

    console.log(`[admin-login] success for "${username}"`);

    return ok(res, {
      message: 'Login successful.',
      admin: { username: admin.username, lastLoginAt: admin.lastLoginAt },
    });
  })
);

// ----------------------------------------------------------------------------
// Admin logout
// ----------------------------------------------------------------------------

app.post(
  '/api/admin/logout',
  asyncHandler(async (req, res) => {
    const token = req.cookies ? req.cookies[CONFIG.ADMIN_COOKIE] : null;
    if (token) await AdminSession.deleteOne({ token, role: 'admin' });
    res.clearCookie(CONFIG.ADMIN_COOKIE, { path: '/' });
    return ok(res, { message: 'Logged out.' });
  })
);

// ----------------------------------------------------------------------------
// Admin session check
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/me',
  requireAdmin,
  asyncHandler(async (req, res) => ok(res, { authenticated: true }))
);

// ----------------------------------------------------------------------------
// Registration toggle + status
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/registration-status',
  requireAdmin,
  asyncHandler(async (req, res) => {
    return ok(res, { open: await isRegistrationOpen() });
  })
);

app.post(
  '/api/admin/registration-toggle',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const next = !(await isRegistrationOpen());
    await setSetting('registration_open', next);

    console.log(`[admin] registration submissions ${next ? 'OPENED' : 'CLOSED'}`);
    sseBroadcast('registration-status', { open: next });

    return ok(res, {
      open: next,
      message: next
        ? 'Student registration submissions are now OPEN.'
        : 'Student registration submissions are now CLOSED.',
    });
  })
);

// ----------------------------------------------------------------------------
// Settings
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/settings',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [registrationOpen, requirePaymentProof, paymentAmount, paymentPhone, maxGroupMembers] =
      await Promise.all([
        isRegistrationOpen(),
        isPaymentProofRequired(),
        getPaymentAmount(),
        getPaymentPhone(),
        getMaxGroupMembers(),
      ]);
    return ok(res, {
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
      maxGroupMembersHardLimit: CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT,
    });
  })
);

app.post(
  '/api/admin/settings',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const body = req.body || {};
    const updates = {};
    const errors = [];

    if (body.registrationOpen !== undefined) {
      updates.registration_open = body.registrationOpen === true;
    }

    if (body.requirePaymentProof !== undefined) {
      updates.require_payment_proof = body.requirePaymentProof === true;
    }

    if (body.paymentAmount !== undefined) {
      const n = Number(body.paymentAmount);
      if (!Number.isFinite(n) || n < 0 || n > 100000) {
        errors.push('Payment amount must be a number between 0 and 100000.');
      } else {
        updates.payment_amount = Math.round(n);
      }
    }

    if (body.paymentPhone !== undefined) {
      const p = normalizePochiPhone(body.paymentPhone);
      if (!p) {
        errors.push('Payment phone must be a valid Kenyan number (e.g. 0741742291).');
      } else {
        updates.payment_phone = p.startsWith('+254') ? '0' + p.slice(4) : p;
      }
    }

    if (body.maxGroupMembers !== undefined) {
      const n = Number(body.maxGroupMembers);
      if (!Number.isFinite(n) || n < 1 || n > CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT) {
        errors.push(`Max group members must be between 1 and ${CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT}.`);
      } else {
        updates.max_group_members = Math.floor(n);
      }
    }

    if (errors.length) return fail(res, errors.join(' '), 'VALIDATION', 400);

    const entries = Object.entries(updates);
    for (const [key, value] of entries) {
      await setSetting(key, value);
    }

    console.log(`[admin] settings updated: ${entries.map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(', ')}`);

    if (updates.registration_open !== undefined) {
      sseBroadcast('registration-status', { open: updates.registration_open });
    }
    sseBroadcast('settings-updated', { keys: entries.map(([k]) => k) });

    const [registrationOpen, requirePaymentProof, paymentAmount, paymentPhone, maxGroupMembers] =
      await Promise.all([
        isRegistrationOpen(),
        isPaymentProofRequired(),
        getPaymentAmount(),
        getPaymentPhone(),
        getMaxGroupMembers(),
      ]);

    return ok(res, {
      message: 'Settings saved.',
      registrationOpen,
      requirePaymentProof,
      paymentAmount,
      paymentPhone,
      maxGroupMembers,
      maxGroupMembersHardLimit: CONFIG.MAX_GROUP_MEMBERS_HARD_LIMIT,
    });
  })
);

// ----------------------------------------------------------------------------
// Paid summary
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/paid-summary',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [total, paid, pending, rejected] = await Promise.all([
      Member.countDocuments(),
      Member.countDocuments({ paymentStatus: 'verified' }),
      Member.countDocuments({ paymentStatus: 'pending' }),
      Member.countDocuments({ paymentStatus: 'rejected' }),
    ]);
    return ok(res, { total, paid, pending, rejected, unpaid: total - paid });
  })
);

// ----------------------------------------------------------------------------
// Paste-and-verify
// ----------------------------------------------------------------------------

/**
 * POST /api/admin/verify-payments
 *
 * Body: { text: '<pasted M-Pesa SMS>' }
 *
 * Extracts codes from the pasted text and verifies matched members.
 * Responds with counts and a full breakdown of the results.
 */
app.post(
  '/api/admin/verify-payments',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const rawText = String(req.body.text || '').trim();
    if (!rawText) return fail(res, 'Paste one or more M-Pesa confirmation messages.', 'VALIDATION', 400);

    const paymentPhone = await getPaymentPhone();
    const entries = extractMpesaEntries(rawText, { excludePhones: [paymentPhone] });

    if (entries.length === 0) {
      return fail(
        res,
        'No M-Pesa codes found in the pasted text. Make sure you paste the full SMS message(s).',
        'NO_CODES_FOUND',
        400
      );
    }

    const verified = [];
    const alreadyVerified = [];
    const unmatched = [];
    const ambiguous = [];

    for (const entry of entries) {
      // 1) Match by exact code.
      let member = await Member.findOne({ mpesaCode: entry.code });

      // 2) Fallback: match by sender phone among pending/rejected/null.
      if (!member && entry.senderPhone) {
        const normalized = normalizePhone(entry.senderPhone);
        if (normalized) {
          const candidates = await Member.find({
            phone: normalized,
            $or: [
              { paymentStatus: null },
              { paymentStatus: 'pending' },
              { paymentStatus: 'rejected' },
            ],
          }).limit(5).lean();

          if (candidates.length === 1) {
            member = await Member.findById(candidates[0]._id);
          } else if (candidates.length > 1) {
            ambiguous.push({
              code: entry.code,
              senderPhone: entry.senderPhone,
              count: candidates.length,
              names: candidates.map((c) => c.name),
            });
            continue;
          }
        }
      }

      if (!member) {
        unmatched.push({ code: entry.code, senderPhone: entry.senderPhone, amount: entry.amount });
        continue;
      }

      if (member.paymentStatus === 'verified') {
        alreadyVerified.push({ code: entry.code, regNo: member.regNo, name: member.name });
        continue;
      }

      // Stamp the code and mark verified.
      member.mpesaCode = entry.code;
      if (!member.paymentAmount && entry.amount) member.paymentAmount = entry.amount;
      if (!member.paymentSubmittedAt) member.paymentSubmittedAt = new Date();
      member.paymentStatus = 'verified';
      member.paymentVerifiedAt = new Date();
      member.paymentVerifiedBy = entry.raw.slice(0, 500);
      member.paymentRejectedReason = null;
      await member.save();

      verified.push({
        id: String(member._id),
        code: entry.code,
        regNo: member.regNo,
        name: member.name,
        phone: member.phone,
      });

      sseBroadcast('member-updated', {
        member: shapeMember(member, { includePayment: true }),
        group: null,
      });
    }

    console.log(
      `[admin] verify-payments: parsed=${entries.length} verified=${verified.length} already=${alreadyVerified.length} unmatched=${unmatched.length} ambiguous=${ambiguous.length}`
    );

    return ok(res, {
      message: 'Extraction complete.',
      total: entries.length,
      verifiedCount: verified.length,
      alreadyVerifiedCount: alreadyVerified.length,
      unmatchedCount: unmatched.length,
      ambiguousCount: ambiguous.length,
      results: { verified, alreadyVerified, unmatched, ambiguous },
    });
  })
);

// ----------------------------------------------------------------------------
// Pending payments
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/pending-payments',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const pending = await Member.find({
      $or: [{ paymentStatus: 'pending' }, { paymentStatus: 'rejected' }],
    })
      .populate('group', 'name')
      .sort({ paymentSubmittedAt: -1, createdAt: -1 })
      .limit(300)
      .lean();

    return ok(res, {
      pending: pending.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        groupName: m.group ? m.group.name : '',
        mpesaCode: m.mpesaCode || null,
        paymentNote: m.paymentNote || null,
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentSubmittedAt: m.paymentSubmittedAt || null,
        paymentStatus: m.paymentStatus || 'pending',
        paymentRejectedReason: m.paymentRejectedReason || null,
        createdAt: m.createdAt,
      })),
    });
  })
);

// ----------------------------------------------------------------------------
// Manual verify / reject
// ----------------------------------------------------------------------------

app.post(
  '/api/admin/members/:id/verify-payment',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid member ID.', 'INVALID_ID', 400);
    const member = await Member.findById(req.params.id);
    if (!member) return fail(res, 'Member not found.', 'NOT_FOUND', 404);

    member.paymentStatus = 'verified';
    member.paymentVerifiedAt = new Date();
    member.paymentVerifiedBy = 'manual:' + String(req.body.note || 'admin verification').slice(0, 400);
    member.paymentRejectedReason = null;
    if (!member.paymentSubmittedAt) member.paymentSubmittedAt = new Date();
    if (!member.paymentAmount) member.paymentAmount = await getPaymentAmount();
    await member.save();

    sseBroadcast('member-updated', { member: shapeMember(member, { includePayment: true }), group: null });
    return ok(res, { message: 'Payment verified.', member: shapeMember(member, { includePayment: true }) });
  })
);

app.post(
  '/api/admin/members/:id/reject-payment',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid member ID.', 'INVALID_ID', 400);
    const member = await Member.findById(req.params.id);
    if (!member) return fail(res, 'Member not found.', 'NOT_FOUND', 404);

    const reason = String(req.body.reason || '').trim().slice(0, 200) || 'Code could not be verified.';
    member.paymentStatus = 'rejected';
    member.paymentRejectedReason = reason;
    await member.save();

    sseBroadcast('member-updated', { member: shapeMember(member, { includePayment: true }), group: null });
    return ok(res, { message: 'Payment rejected.', member: shapeMember(member, { includePayment: true }) });
  })
);

// ----------------------------------------------------------------------------
// Dashboard
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/dashboard',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [totalMembers, totalGroups, totalLeaders, maxGroupMembers, verifiedCount, pendingCount, rejectedCount] =
      await Promise.all([
        Member.countDocuments(),
        Group.countDocuments(),
        Member.countDocuments({ isLeader: true }),
        getMaxGroupMembers(),
        Member.countDocuments({ paymentStatus: 'verified' }),
        Member.countDocuments({ paymentStatus: 'pending' }),
        Member.countDocuments({ paymentStatus: 'rejected' }),
      ]);

    const groups = await Group.find().sort({ createdAt: 1 }).lean();
    const leaders = await Member.find({ isLeader: true }).select('regNo name group').lean();
    const leaderByGroup = {};
    for (const l of leaders) leaderByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };

    const recent = await Member.find()
      .sort({ createdAt: -1 })
      .limit(10)
      .populate('group', 'name')
      .lean();

    return ok(res, {
      totals: {
        totalMembers,
        totalGroups,
        totalLeaders,
        paid: verifiedCount,
        pending: pendingCount,
        rejected: rejectedCount,
        unpaid: totalMembers - verifiedCount,
      },
      maxGroupMembers,
      groups: groups.map((g) =>
        shapeGroup(g, {
          capacity: maxGroupMembers,
          leaderName: leaderByGroup[String(g._id)]?.name || null,
          leaderRegNo: leaderByGroup[String(g._id)]?.regNo || null,
        })
      ),
      recent: recent.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        isLeader: Boolean(m.isLeader),
        role: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
        groupName: m.group ? m.group.name : null,
        createdAt: m.createdAt,
        mpesaCode: m.mpesaCode || null,
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentNote: m.paymentNote || null,
        paymentSubmittedAt: m.paymentSubmittedAt || null,
        paymentStatus: m.paymentStatus || null,
      })),
    });
  })
);

// ----------------------------------------------------------------------------
// Groups CRUD
// ----------------------------------------------------------------------------

app.get(
  '/api/admin/groups',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const [groups, leaders, maxGroupMembers] = await Promise.all([
      Group.find().sort({ createdAt: 1 }).lean(),
      Member.find({ isLeader: true }).select('regNo name group').lean(),
      getMaxGroupMembers(),
    ]);
    const leaderByGroup = {};
    for (const l of leaders) leaderByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };
    return ok(res, {
      groups: groups.map((g) =>
        shapeGroup(g, {
          capacity: maxGroupMembers,
          leaderName: leaderByGroup[String(g._id)]?.name || null,
          leaderRegNo: leaderByGroup[String(g._id)]?.regNo || null,
        })
      ),
    });
  })
);

app.get(
  '/api/admin/groups/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid group ID.', 'INVALID_ID', 400);

    const group = await Group.findById(req.params.id);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const [members, maxGroupMembers] = await Promise.all([
      Member.find({ group: group._id }).sort({ isLeader: -1, createdAt: 1 }).lean(),
      getMaxGroupMembers(),
    ]);
    const leader = members.find((m) => m.isLeader) || null;

    return ok(res, {
      group: {
        ...shapeGroup(group, { capacity: maxGroupMembers }),
        leaderName: leader ? leader.name : null,
        leaderRegNo: leader ? leader.regNo : null,
      },
      members: members.map((m) => ({
        id: String(m._id),
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        isLeader: Boolean(m.isLeader),
        role: m.isLeader ? 'GROUP LEADER' : 'MEMBER',
        createdAt: m.createdAt,
        mpesaCode: m.mpesaCode || null,
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentNote: m.paymentNote || null,
        paymentSubmittedAt: m.paymentSubmittedAt || null,
        paymentStatus: m.paymentStatus || null,
        paymentRejectedReason: m.paymentRejectedReason || null,
      })),
    });
  })
);

app.post(
  '/api/admin/groups',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const display = displayGroupName(req.body.name);
    const norm = normalizeGroupName(req.body.name);
    if (!isValidGroupName(norm)) return fail(res, 'Please provide a valid group name.', 'INVALID_GROUP', 400);

    const existing = await Group.findOne({ normalizedName: norm });
    if (existing) return fail(res, 'A group with that name already exists.', 'DUPLICATE_GROUP', 409);

    const group = await Group.create({ name: display, normalizedName: norm, memberCount: 0 });
    const maxGroupMembers = await getMaxGroupMembers();

    console.log(`[admin] created group "${group.name}"`);
    sseBroadcast('group-created', { group: shapeGroup(group, { capacity: maxGroupMembers }) });

    return ok(res, { message: 'Group created.', group: shapeGroup(group, { capacity: maxGroupMembers }) }, 201);
  })
);

app.patch(
  '/api/admin/groups/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid group ID.', 'INVALID_ID', 400);
    const group = await Group.findById(req.params.id);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const display = displayGroupName(req.body.name);
    const norm = normalizeGroupName(req.body.name);
    if (!isValidGroupName(norm)) return fail(res, 'Please provide a valid group name.', 'INVALID_GROUP', 400);

    const clash = await Group.findOne({ normalizedName: norm, _id: { $ne: group._id } });
    if (clash) return fail(res, 'Another group already uses that name.', 'DUPLICATE_GROUP', 409);

    const oldName = group.name;
    group.name = display;
    group.normalizedName = norm;
    await group.save();

    const maxGroupMembers = await getMaxGroupMembers();
    console.log(`[admin] renamed group "${oldName}" → "${display}"`);
    sseBroadcast('group-updated', { group: shapeGroup(group, { capacity: maxGroupMembers }) });

    return ok(res, { message: 'Group renamed.', group: shapeGroup(group, { capacity: maxGroupMembers }) });
  })
);

app.delete(
  '/api/admin/groups/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid group ID.', 'INVALID_ID', 400);
    const group = await Group.findById(req.params.id);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const memberCount = await Member.countDocuments({ group: group._id });
    const confirm = String(req.query.confirm || '').toLowerCase() === 'true';

    if (memberCount > 0 && !confirm) {
      return fail(
        res,
        `This group contains ${memberCount} member(s). To delete the group and all of its members, resend with ?confirm=true.`,
        'CONFIRM_REQUIRED',
        409
      );
    }

    await Member.deleteMany({ group: group._id });
    await Group.deleteOne({ _id: group._id });

    console.log(`[admin] deleted group "${group.name}" (members=${memberCount})`);
    sseBroadcast('group-deleted', { groupId: String(group._id), name: group.name });

    return ok(res, {
      message: `Group and ${memberCount} member(s) deleted.`,
      deletedMembers: memberCount,
    });
  })
);

// ----------------------------------------------------------------------------
// Members CRUD (admin)
// ----------------------------------------------------------------------------

app.post(
  '/api/admin/members',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const regNo = normalizeRegNo(req.body.regNo);
    const name = normalizeName(req.body.name);
    const phone = normalizePhone(req.body.phone);
    const groupId = req.body.groupId;
    const mpesaCode = normalizeMpesaCode(req.body.mpesaCode);
    const paymentNote = sanitizePaymentNote(req.body.paymentNote);

    if (!isValidRegNo(regNo)) return fail(res, 'Invalid registration number.', 'INVALID_REQNO', 400);
    if (!isValidName(name)) return fail(res, 'Invalid full name.', 'INVALID_NAME', 400);
    if (!phone) return fail(res, 'Invalid Kenyan phone number.', 'INVALID_PHONE', 400);
    if (!mongoose.isValidObjectId(groupId)) return fail(res, 'Invalid group.', 'INVALID_GROUP', 400);

    const group = await Group.findById(groupId);
    if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

    const dupReg = await Member.findOne({ regNo });
    if (dupReg) return fail(res, 'This registration number has already been registered.', 'DUPLICATE_REGNO', 409);

    if (mpesaCode) {
      const codeCheck = validateMpesaCodeHard(mpesaCode);
      if (!codeCheck.valid) return fail(res, codeCheck.reason, 'INVALID_MPESA_CODE', 400);

      const dupCode = await Member.findOne({ mpesaCode }).lean();
      if (dupCode) return fail(res, 'This M-Pesa code has already been used.', 'DUPLICATE_MPESA_CODE', 409);
    }

    const maxGroupMembers = await getMaxGroupMembers();
    const paymentAmount = await getPaymentAmount();

    // Atomic capacity check.
    const incremented = await Group.findOneAndUpdate(
      { _id: group._id, memberCount: { $lt: maxGroupMembers } },
      { $inc: { memberCount: 1 } },
      { new: true }
    );
    if (!incremented) {
      return fail(res, `This group is already full. Maximum is ${maxGroupMembers} members.`, 'GROUP_FULL', 409);
    }

    const isLeader = incremented.memberCount === 1;
    let member;
    try {
      member = await Member.create({
        regNo,
        name,
        phone,
        group: group._id,
        isLeader,
        mpesaCode: mpesaCode || null,
        paymentAmount: mpesaCode ? paymentAmount : null,
        paymentNote: paymentNote || null,
        paymentSubmittedAt: mpesaCode ? new Date() : null,
        paymentStatus: mpesaCode ? 'pending' : null,
      });
    } catch (err) {
      await Group.updateOne({ _id: group._id }, { $inc: { memberCount: -1 } });
      if (err && err.code === 11000) {
        const keys = err.keyPattern || {};
        if (keys.regNo) return fail(res, 'This registration number has already been registered.', 'DUPLICATE_REGNO', 409);
        if (keys.mpesaCode) return fail(res, 'This M-Pesa code has already been used.', 'DUPLICATE_MPESA_CODE', 409);
      }
      throw err;
    }

    if (isLeader) await Group.updateOne({ _id: group._id, leader: null }, { $set: { leader: member._id } });
    await reconcileGroupLeader(group._id);

    const freshGroup = await Group.findById(group._id);
    sseBroadcast('member-added', {
      member: shapeMember(member, { includePayment: true }),
      group: shapeGroup(freshGroup, { capacity: maxGroupMembers }),
    });

    return ok(res, { message: 'Member added.', member: shapeMember(member, { includePayment: true }) }, 201);
  })
);

app.patch(
  '/api/admin/members/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid member ID.', 'INVALID_ID', 400);
    const member = await Member.findById(req.params.id);
    if (!member) return fail(res, 'Member not found.', 'NOT_FOUND', 404);

    const oldGroupId = member.group;
    const newRegNo = req.body.regNo !== undefined ? normalizeRegNo(req.body.regNo) : member.regNo;
    const newName = req.body.name !== undefined ? normalizeName(req.body.name) : member.name;
    const newPhoneRaw = req.body.phone !== undefined ? req.body.phone : member.phone;
    const newPhone = normalizePhone(newPhoneRaw);
    const newGroupId = req.body.groupId !== undefined ? req.body.groupId : String(member.group);

    if (!isValidRegNo(newRegNo)) return fail(res, 'Invalid registration number.', 'INVALID_REQNO', 400);
    if (!isValidName(newName)) return fail(res, 'Invalid full name.', 'INVALID_NAME', 400);
    if (!newPhone) return fail(res, 'Invalid Kenyan phone number.', 'INVALID_PHONE', 400);
    if (!mongoose.isValidObjectId(newGroupId)) return fail(res, 'Invalid group.', 'INVALID_GROUP', 400);

    const clash = await Member.findOne({ regNo: newRegNo, _id: { $ne: member._id } });
    if (clash) return fail(res, 'Another member already uses this registration number.', 'DUPLICATE_REGNO', 409);

    const movingGroup = String(newGroupId) !== String(oldGroupId);
    const maxGroupMembers = await getMaxGroupMembers();

    if (movingGroup) {
      const target = await Group.findById(newGroupId);
      if (!target) return fail(res, 'Target group not found.', 'NOT_FOUND', 404);

      const incremented = await Group.findOneAndUpdate(
        { _id: target._id, memberCount: { $lt: maxGroupMembers } },
        { $inc: { memberCount: 1 } },
        { new: true }
      );
      if (!incremented) return fail(res, 'Target group is already full.', 'GROUP_FULL', 409);

      member.regNo = newRegNo;
      member.name = newName;
      member.phone = newPhone;
      member.group = target._id;
      member.isLeader = false;
      await member.save();

      await Group.updateOne({ _id: oldGroupId }, { $inc: { memberCount: -1 } });
      await reconcileGroupLeader(oldGroupId);
      await reconcileGroupLeader(target._id);
    } else {
      member.regNo = newRegNo;
      member.name = newName;
      member.phone = newPhone;
      await member.save();
      await reconcileGroupLeader(member.group);
    }

    // Optional payment fields.
    if (req.body.mpesaCode !== undefined) {
      const code = normalizeMpesaCode(req.body.mpesaCode);
      if (code) {
        const codeCheck = validateMpesaCodeHard(code);
        if (!codeCheck.valid) return fail(res, codeCheck.reason, 'INVALID_MPESA_CODE', 400);
        const dupCode = await Member.findOne({ mpesaCode: code, _id: { $ne: member._id } });
        if (dupCode) return fail(res, 'This M-Pesa code has already been used.', 'DUPLICATE_MPESA_CODE', 409);
      }
      member.mpesaCode = code || null;
      member.paymentSubmittedAt = code ? new Date() : null;
      if (code) {
        if (!member.paymentAmount) member.paymentAmount = await getPaymentAmount();
        if (!member.paymentStatus) member.paymentStatus = 'pending';
      }
    }
    if (req.body.paymentNote !== undefined) {
      member.paymentNote = sanitizePaymentNote(req.body.paymentNote) || null;
    }
    await member.save();

    const freshGroup = await Group.findById(member.group);
    const freshMember = await Member.findById(member._id);

    sseBroadcast('member-updated', {
      member: shapeMember(freshMember, { includePayment: true }),
      group: shapeGroup(freshGroup, { capacity: maxGroupMembers }),
    });

    return ok(res, { message: 'Member updated.', member: shapeMember(freshMember, { includePayment: true }) });
  })
);

app.delete(
  '/api/admin/members/:id',
  requireAdmin,
  asyncHandler(async (req, res) => {
    if (!mongoose.isValidObjectId(req.params.id)) return fail(res, 'Invalid member ID.', 'INVALID_ID', 400);
    const member = await Member.findById(req.params.id);
    if (!member) return fail(res, 'Member not found.', 'NOT_FOUND', 404);

    const groupId = member.group;
    await Member.deleteOne({ _id: member._id });
    await Group.updateOne({ _id: groupId }, { $inc: { memberCount: -1 } });
    await reconcileGroupLeader(groupId);

    const freshGroup = await Group.findById(groupId);
    const maxGroupMembers = await getMaxGroupMembers();

    sseBroadcast('member-deleted', {
      memberId: String(member._id),
      group: freshGroup ? shapeGroup(freshGroup, { capacity: maxGroupMembers }) : null,
    });

    console.log(`[admin] deleted member ${member.regNo} from group ${groupId}`);
    return ok(res, { message: 'Member deleted.' });
  })
);

/* ============================================================================
 * SECTION 12 — CSV EXPORT
 * ============================================================================
 *
 * Clean columns, no payment data. Sorted by group name then registration
 * date. Excel-friendly (BOM prefixed).
 * ========================================================================== */

/**
 * Escape a value for CSV output.
 * @param {any} value
 * @returns {string}
 */
function csvEscape(value) {
  if (value == null) return '';
  const s = String(value);
  if (/[",\n\r]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
  return s;
}

app.get(
  '/api/admin/export',
  requireAdmin,
  asyncHandler(async (req, res) => {
    const members = await Member.find().populate('group', 'name normalizedName').lean();

    members.sort((a, b) => {
      const ga = (a.group && a.group.name ? a.group.name : '').toLowerCase();
      const gb = (b.group && b.group.name ? b.group.name : '').toLowerCase();
      if (ga < gb) return -1;
      if (ga > gb) return 1;
      return new Date(a.createdAt) - new Date(b.createdAt);
    });

    const header = ['GROUP NAME', 'REG NO', 'NAME', 'PHONE NUMBER', 'ROLE', 'REGISTRATION DATE'];
    const lines = [header.join(',')];

    for (const m of members) {
      lines.push([
        csvEscape(m.group ? m.group.name : ''),
        csvEscape(m.regNo),
        csvEscape(m.name),
        csvEscape(m.phone),
        csvEscape(m.isLeader ? 'GROUP LEADER' : 'MEMBER'),
        csvEscape(new Date(m.createdAt).toISOString()),
      ].join(','));
    }

    const csv = lines.join('\r\n');
    const filename = `physics-education-groups-${new Date().toISOString().slice(0, 10)}.csv`;

    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    return res.status(200).send('\uFEFF' + csv);
  })
);

/* ============================================================================
 * SECTION 13 — PDF EXPORT
 * ============================================================================
 *
 * Three PDFs:
 *   /api/admin/export/pdf         — clean group registry (all groups)
 *   /api/admin/export/paid/pdf    — verified payments only
 *   /api/member/export/pdf        — own group only
 * ========================================================================== */

// Palette used by every PDF.
const PDF_COLORS = {
  textDark: '#111827',
  text: '#1f2937',
  textMuted: '#6b7280',
  border: '#d1d5db',
  borderLight: '#e5e7eb',
  bgSubtle: '#f9fafb',
  bgLight: '#f3f4f6',
  bgMedium: '#e5e7eb',
  white: '#ffffff',
  successText: '#15803d',
  dangerText: '#b91c1c',
};

const PDF_LAYOUT = Object.freeze({
  pageSize: 'A4',
  margin: 50,
  footerHeight: 40,
});

const A4_WIDTH = 595.28;
const A4_HEIGHT = 841.89;

/** Format a date with month name, suitable for the PDF header. */
function pdfFmtLong(d) {
  try {
    return new Date(d).toLocaleString('en-GB', {
      day: '2-digit', month: 'long', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return ''; }
}

/** Short date format used inside payment rows. */
function pdfFmtShort(d) {
  try {
    return new Date(d).toLocaleString('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  } catch (_) { return ''; }
}

/** Draw the standard page header at the top of every page. */
function pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle }) {
  doc.save();
  doc.rect(0, 0, pageWidth, 3).fill(PDF_COLORS.textDark);
  doc.restore();

  doc.fillColor(PDF_COLORS.textDark).fontSize(18).font('Helvetica-Bold');
  doc.text('PHYSICS EDUCATION GROUPS', PDF_LAYOUT.margin, 26, {
    width: contentWidth, align: 'left', lineBreak: false,
  });

  doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.textMuted);
  doc.text(String(reportTitle || '').toUpperCase(), PDF_LAYOUT.margin, 52, {
    width: contentWidth * 0.6, align: 'left', lineBreak: false,
  });

  doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.textMuted);
  doc.text('Generated: ' + pdfFmtLong(new Date()), PDF_LAYOUT.margin + contentWidth * 0.6, 53, {
    width: contentWidth * 0.4, align: 'right', lineBreak: false,
  });

  doc.save();
  doc.moveTo(PDF_LAYOUT.margin, 74)
    .lineTo(pageWidth - PDF_LAYOUT.margin, 74)
    .strokeColor(PDF_COLORS.border).lineWidth(0.5).stroke();
  doc.restore();
}

/** Draw the page footer (confidential note + page number). */
function pdfDrawFooter(doc, { pageWidth, pageHeight, contentWidth }) {
  const range = doc.bufferedPageRange();
  const totalPages = range.count;
  const contentLeft = PDF_LAYOUT.margin;
  const contentRight = pageWidth - PDF_LAYOUT.margin;

  for (let i = 0; i < totalPages; i++) {
    doc.switchToPage(range.start + i);
    const footerY = pageHeight - 40;

    doc.save();
    doc.moveTo(contentLeft, footerY - 8)
      .lineTo(contentRight, footerY - 8)
      .strokeColor(PDF_COLORS.borderLight).lineWidth(0.5).stroke();
    doc.restore();

    doc.fontSize(7.5).font('Helvetica').fillColor(PDF_COLORS.textMuted);
    doc.text(
      'Physics Education Groups  •  Confidential administrative document',
      contentLeft, footerY, { width: contentWidth * 0.7, align: 'left', lineBreak: false }
    );
    doc.text(
      `Page ${i + 1} of ${totalPages}`,
      contentLeft + contentWidth * 0.7, footerY,
      { width: contentWidth * 0.3, align: 'right', lineBreak: false }
    );
  }
}

/**
 * Build the clean group registry PDF (all groups + all members).
 * @returns {Promise<Buffer>}
 */
function buildGroupsPdf({ groups, reportTitle, reportSubtitle, maxGroupMembers }) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: PDF_LAYOUT.pageSize,
        margins: {
          top: PDF_LAYOUT.margin,
          bottom: PDF_LAYOUT.margin + 20,
          left: PDF_LAYOUT.margin,
          right: PDF_LAYOUT.margin,
        },
        bufferPages: true,
        autoFirstPage: false,
        info: {
          Title: reportTitle,
          Author: 'Physics Education Groups',
          Subject: 'Group Registry',
          Creator: 'Physics Education Groups',
        },
      });

      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      doc.addPage();

      const pageWidth = (doc.page && doc.page.width) || A4_WIDTH;
      const pageHeight = (doc.page && doc.page.height) || A4_HEIGHT;
      const contentWidth = pageWidth - PDF_LAYOUT.margin * 2;
      const contentLeft = PDF_LAYOUT.margin;
      const contentRight = pageWidth - PDF_LAYOUT.margin;
      const capacity = maxGroupMembers || CONFIG.MAX_GROUP_MEMBERS_DEFAULT;

      const totals = groups.reduce(
        (acc, g) => {
          acc.groups += 1;
          acc.members += (g.members || []).length;
          acc.leaders += (g.members || []).filter((m) => m.isLeader).length;
          return acc;
        },
        { groups: 0, members: 0, leaders: 0 }
      );

      const rawCols = { idx: 28, regNo: 90, name: 165, phone: 100, role: 112 };
      const totalRaw = rawCols.idx + rawCols.regNo + rawCols.name + rawCols.phone + rawCols.role;
      const scale = contentWidth / totalRaw;
      const colWidths = {
        idx: rawCols.idx * scale,
        regNo: rawCols.regNo * scale,
        name: rawCols.name * scale,
        phone: rawCols.phone * scale,
        role: rawCols.role * scale,
      };
      const colX = {
        idx: contentLeft,
        regNo: contentLeft + colWidths.idx,
        name: contentLeft + colWidths.idx + colWidths.regNo,
        phone: contentLeft + colWidths.idx + colWidths.regNo + colWidths.name,
        role: contentLeft + colWidths.idx + colWidths.regNo + colWidths.name + colWidths.phone,
      };

      pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });

      let y = 92;
      if (reportSubtitle) {
        doc.fontSize(10).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text(reportSubtitle, contentLeft, y, { width: contentWidth, align: 'left' });
        y += 16;
      }

      // Summary box
      const summaryBoxHeight = 62;
      doc.save();
      doc.roundedRect(contentLeft, y, contentWidth, summaryBoxHeight, 4)
        .fillAndStroke(PDF_COLORS.bgSubtle, PDF_COLORS.border);
      doc.restore();

      const summaryItems = [
        { label: 'TOTAL GROUPS', value: String(totals.groups) },
        { label: 'TOTAL MEMBERS', value: String(totals.members) },
        { label: 'GROUP LEADERS', value: String(totals.leaders) },
        { label: 'CAPACITY PER GROUP', value: String(capacity) },
      ];
      const itemWidth = contentWidth / summaryItems.length;
      summaryItems.forEach((item, i) => {
        const ix = contentLeft + i * itemWidth + 14;
        doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textMuted);
        doc.text(item.label, ix, y + 12, { width: itemWidth - 20, align: 'left' });
        doc.fontSize(17).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(item.value, ix, y + 26, { width: itemWidth - 20, align: 'left' });
      });
      y += summaryBoxHeight + 22;

      function ensureSpace(needed) {
        if (y + needed > pageHeight - PDF_LAYOUT.margin - PDF_LAYOUT.footerHeight + 10) {
          doc.addPage();
          pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });
          y = 92;
        }
      }

      function drawGroupHeader(group, index) {
        ensureSpace(80);
        const headerHeight = 44;

        doc.save();
        doc.roundedRect(contentLeft, y, contentWidth, headerHeight, 4)
          .fillAndStroke(PDF_COLORS.bgLight, PDF_COLORS.border);
        doc.restore();

        doc.save();
        doc.circle(contentLeft + 24, y + headerHeight / 2, 13)
          .fillAndStroke(PDF_COLORS.white, PDF_COLORS.textDark);
        doc.restore();

        doc.fontSize(11).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(String(index), contentLeft + 18, y + headerHeight / 2 - 6, { width: 12, align: 'center' });

        doc.fontSize(13).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(group.name, contentLeft + 48, y + 8, {
          width: contentWidth - 200, align: 'left', lineBreak: false, ellipsis: true,
        });

        doc.fontSize(8.5).font('Helvetica').fillColor(PDF_COLORS.textMuted);
        const metaParts = [`${(group.members || []).length} / ${capacity} members`];
        if (group.leaderName) {
          metaParts.push(`Leader: ${group.leaderName}${group.leaderRegNo ? ' (' + group.leaderRegNo + ')' : ''}`);
        }
        doc.text(metaParts.join('   •   '), contentLeft + 48, y + 26, {
          width: contentWidth - 60, align: 'left', lineBreak: false, ellipsis: true,
        });

        const isFull = (group.members || []).length >= capacity;
        const badgeText = isFull ? 'FULL' : 'OPEN';
        const badgeColor = isFull ? PDF_COLORS.dangerText : PDF_COLORS.successText;
        const badgeWidth = 44;
        const badgeX = contentRight - badgeWidth - 12;
        doc.save();
        doc.roundedRect(badgeX, y + 13, badgeWidth, 18, 9)
          .fillAndStroke(PDF_COLORS.white, badgeColor);
        doc.restore();
        doc.fontSize(8).font('Helvetica-Bold').fillColor(badgeColor);
        doc.text(badgeText, badgeX, y + 18, { width: badgeWidth, align: 'center' });

        y += headerHeight + 8;

        // Table header
        doc.save();
        doc.rect(contentLeft, y, contentWidth, 22).fill(PDF_COLORS.bgMedium);
        doc.restore();

        const headerY = y + 7;
        doc.fontSize(8).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text('#', colX.idx + 4, headerY, { width: colWidths.idx - 8, align: 'left', lineBreak: false });
        doc.text('REG NO', colX.regNo + 6, headerY, { width: colWidths.regNo - 8, align: 'left', lineBreak: false });
        doc.text('NAME', colX.name + 6, headerY, { width: colWidths.name - 8, align: 'left', lineBreak: false });
        doc.text('PHONE NUMBER', colX.phone + 6, headerY, { width: colWidths.phone - 8, align: 'left', lineBreak: false });
        doc.text('ROLE', colX.role + 6, headerY, { width: colWidths.role - 8, align: 'left', lineBreak: false });
        y += 22;
      }

      function drawMemberRow(m, idx, isLeader) {
        const rowHeight = 22;
        ensureSpace(rowHeight + 2);

        if (isLeader) {
          doc.save();
          doc.rect(contentLeft, y, contentWidth, rowHeight).fill(PDF_COLORS.bgLight);
          doc.restore();
          doc.save();
          doc.rect(contentLeft, y, 2, rowHeight).fill(PDF_COLORS.textDark);
          doc.restore();
        } else if (idx % 2 === 1) {
          doc.save();
          doc.rect(contentLeft, y, contentWidth, rowHeight).fill(PDF_COLORS.bgSubtle);
          doc.restore();
        }

        const cellY = y + 7;
        doc.fontSize(9).font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(String(idx), colX.idx + 4, cellY, {
          width: colWidths.idx - 8, align: 'left', lineBreak: false, ellipsis: true,
        });

        doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(m.regNo || '', colX.regNo + 6, cellY, {
          width: colWidths.regNo - 8, align: 'left', lineBreak: false, ellipsis: true,
        });

        doc.font(isLeader ? 'Helvetica-Bold' : 'Helvetica').fillColor(PDF_COLORS.text);
        doc.text(m.name || '', colX.name + 6, cellY, {
          width: colWidths.name - 8, align: 'left', lineBreak: false, ellipsis: true,
        });

        doc.font('Helvetica').fillColor(PDF_COLORS.textMuted);
        doc.text(m.phone || '', colX.phone + 6, cellY, {
          width: colWidths.phone - 8, align: 'left', lineBreak: false, ellipsis: true,
        });

        if (isLeader) {
          doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
          doc.text('GROUP LEADER', colX.role + 6, cellY, {
            width: colWidths.role - 8, align: 'left', lineBreak: false, ellipsis: true,
          });
        } else {
          doc.font('Helvetica').fillColor(PDF_COLORS.textMuted);
          doc.text('MEMBER', colX.role + 6, cellY, {
            width: colWidths.role - 8, align: 'left', lineBreak: false, ellipsis: true,
          });
        }

        doc.save();
        doc.moveTo(contentLeft, y + rowHeight)
          .lineTo(contentRight, y + rowHeight)
          .strokeColor(PDF_COLORS.borderLight).lineWidth(0.4).stroke();
        doc.restore();

        y += rowHeight;
      }

      if (groups.length === 0) {
        doc.fontSize(11).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text('No groups have been registered yet.', contentLeft, y + 20, {
          width: contentWidth, align: 'center',
        });
      } else {
        groups.forEach((group, gi) => {
          drawGroupHeader(group, gi + 1);
          const members = group.members || [];
          if (members.length === 0) {
            const emptyHeight = 26;
            doc.save();
            doc.rect(contentLeft, y, contentWidth, emptyHeight)
              .fillAndStroke(PDF_COLORS.bgSubtle, PDF_COLORS.border);
            doc.restore();
            doc.fontSize(9).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
            doc.text('No members in this group yet.', contentLeft + 8, y + 8, {
              width: contentWidth - 16, align: 'left',
            });
            y += emptyHeight;
          } else {
            members.forEach((m, mi) => drawMemberRow(m, mi + 1, Boolean(m.isLeader)));
          }
          y += 18;
        });
      }

      pdfDrawFooter(doc, { pageWidth, pageHeight, contentWidth });
      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

/**
 * Build the verified-payments-only PDF.
 * @returns {Promise<Buffer>}
 */
function buildPaidMembersPdf({ rows, reportTitle, reportSubtitle }) {
  return new Promise((resolve, reject) => {
    try {
      const doc = new PDFDocument({
        size: PDF_LAYOUT.pageSize,
        margins: {
          top: PDF_LAYOUT.margin,
          bottom: PDF_LAYOUT.margin + 20,
          left: PDF_LAYOUT.margin,
          right: PDF_LAYOUT.margin,
        },
        bufferPages: true,
        autoFirstPage: false,
        info: {
          Title: reportTitle,
          Author: 'Physics Education Groups',
          Subject: 'Verified Payments',
          Creator: 'Physics Education Groups',
        },
      });

      const chunks = [];
      doc.on('data', (c) => chunks.push(c));
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', (err) => reject(err));

      doc.addPage();

      const pageWidth = (doc.page && doc.page.width) || A4_WIDTH;
      const pageHeight = (doc.page && doc.page.height) || A4_HEIGHT;
      const contentWidth = pageWidth - PDF_LAYOUT.margin * 2;
      const contentLeft = PDF_LAYOUT.margin;
      const contentRight = pageWidth - PDF_LAYOUT.margin;

      const totals = {
        count: rows.length,
        totalAmount: rows.reduce((a, r) => a + (Number(r.paymentAmount) || 0), 0),
        groups: new Set(rows.map((r) => r.groupName)).size,
      };

      const rawCols = {
        idx: 22, group: 92, regNo: 66, name: 100, phone: 66,
        mpesa: 60, amount: 40, note: 80, paidAt: 72,
      };
      const totalRaw = Object.values(rawCols).reduce((a, b) => a + b, 0);
      const scale = contentWidth / totalRaw;
      const colWidths = {};
      const colX = {};
      let accum = 0;
      for (const [key, w] of Object.entries(rawCols)) {
        colX[key] = contentLeft + accum * scale;
        colWidths[key] = w * scale;
        accum += w;
      }

      pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });
      let y = 92;

      if (reportSubtitle) {
        doc.fontSize(10).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text(reportSubtitle, contentLeft, y, { width: contentWidth, align: 'left' });
        y += 16;
      }

      const summaryBoxHeight = 62;
      doc.save();
      doc.roundedRect(contentLeft, y, contentWidth, summaryBoxHeight, 4)
        .fillAndStroke(PDF_COLORS.bgSubtle, PDF_COLORS.border);
      doc.restore();

      const summaryItems = [
        { label: 'VERIFIED PAYMENTS', value: String(totals.count) },
        { label: 'GROUPS WITH PAYMENTS', value: String(totals.groups) },
        { label: 'TOTAL AMOUNT (KSH)', value: String(totals.totalAmount) },
        { label: 'REPORT TYPE', value: 'VERIFIED' },
      ];
      const itemWidth = contentWidth / summaryItems.length;
      summaryItems.forEach((item, i) => {
        const ix = contentLeft + i * itemWidth + 14;
        doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textMuted);
        doc.text(item.label, ix, y + 12, { width: itemWidth - 20, align: 'left' });
        doc.fontSize(17).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(item.value, ix, y + 26, { width: itemWidth - 20, align: 'left' });
      });
      y += summaryBoxHeight + 22;

      function ensureSpace(needed) {
        if (y + needed > pageHeight - PDF_LAYOUT.margin - PDF_LAYOUT.footerHeight + 10) {
          doc.addPage();
          pdfDrawHeader(doc, { pageWidth, contentWidth, reportTitle });
          y = 92;
        }
      }

      // Header row
      ensureSpace(40);
      doc.save();
      doc.rect(contentLeft, y, contentWidth, 22).fill(PDF_COLORS.bgMedium);
      doc.restore();

      const headerY = y + 7;
      doc.fontSize(7.5).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
      doc.text('#', colX.idx + 3, headerY, { width: colWidths.idx - 6, align: 'left', lineBreak: false });
      doc.text('GROUP', colX.group + 4, headerY, { width: colWidths.group - 8, align: 'left', lineBreak: false });
      doc.text('REG NO', colX.regNo + 4, headerY, { width: colWidths.regNo - 8, align: 'left', lineBreak: false });
      doc.text('NAME', colX.name + 4, headerY, { width: colWidths.name - 8, align: 'left', lineBreak: false });
      doc.text('PHONE', colX.phone + 4, headerY, { width: colWidths.phone - 8, align: 'left', lineBreak: false });
      doc.text('M-PESA', colX.mpesa + 4, headerY, { width: colWidths.mpesa - 8, align: 'left', lineBreak: false });
      doc.text('KSH', colX.amount + 4, headerY, { width: colWidths.amount - 8, align: 'left', lineBreak: false });
      doc.text('NOTE', colX.note + 4, headerY, { width: colWidths.note - 8, align: 'left', lineBreak: false });
      doc.text('PAID AT', colX.paidAt + 4, headerY, { width: colWidths.paidAt - 8, align: 'left', lineBreak: false });
      y += 22;

      function drawRow(r, idx) {
        const rowHeight = 24;
        ensureSpace(rowHeight + 2);

        if (idx % 2 === 1) {
          doc.save();
          doc.rect(contentLeft, y, contentWidth, rowHeight).fill(PDF_COLORS.bgSubtle);
          doc.restore();
        }

        const cellY = y + 8;
        doc.fontSize(8).font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(String(idx), colX.idx + 3, cellY, { width: colWidths.idx - 6, align: 'left', lineBreak: false, ellipsis: true });
        doc.text(r.groupName || '', colX.group + 4, cellY, { width: colWidths.group - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(r.regNo || '', colX.regNo + 4, cellY, { width: colWidths.regNo - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(r.name || '', colX.name + 4, cellY, { width: colWidths.name - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.fillColor(PDF_COLORS.textMuted);
        doc.text(r.phone || '', colX.phone + 4, cellY, { width: colWidths.phone - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(r.mpesaCode || '', colX.mpesa + 4, cellY, { width: colWidths.mpesa - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.font('Helvetica').fillColor(PDF_COLORS.text);
        doc.text(r.paymentAmount != null ? String(r.paymentAmount) : '', colX.amount + 4, cellY, { width: colWidths.amount - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.fillColor(PDF_COLORS.textMuted);
        doc.text(r.paymentNote || '', colX.note + 4, cellY, { width: colWidths.note - 8, align: 'left', lineBreak: false, ellipsis: true });
        doc.fontSize(7.5).fillColor(PDF_COLORS.textMuted);
        doc.text(r.paymentSubmittedAt ? pdfFmtShort(r.paymentSubmittedAt) : '', colX.paidAt + 4, cellY + 1, { width: colWidths.paidAt - 8, align: 'left', lineBreak: false, ellipsis: true });

        doc.save();
        doc.moveTo(contentLeft, y + rowHeight)
          .lineTo(contentRight, y + rowHeight)
          .strokeColor(PDF_COLORS.borderLight).lineWidth(0.4).stroke();
        doc.restore();

        y += rowHeight;
      }

      if (rows.length === 0) {
        doc.fontSize(11).font('Helvetica-Oblique').fillColor(PDF_COLORS.textMuted);
        doc.text('No verified payments recorded yet.', contentLeft, y + 20, {
          width: contentWidth, align: 'center',
        });
      } else {
        rows.forEach((r, i) => drawRow(r, i + 1));

        y += 12;
        ensureSpace(30);
        doc.save();
        doc.moveTo(contentLeft, y).lineTo(contentRight, y)
          .strokeColor(PDF_COLORS.border).lineWidth(0.7).stroke();
        doc.restore();

        doc.fontSize(10).font('Helvetica-Bold').fillColor(PDF_COLORS.textDark);
        doc.text(
          `Total verified: ${totals.count} member(s)  •  Total collected: KSH ${totals.totalAmount}`,
          contentLeft, y + 8, { width: contentWidth, align: 'right' }
        );
      }

      pdfDrawFooter(doc, { pageWidth, pageHeight, contentWidth });
      doc.end();
    } catch (err) {
      reject(err);
    }
  });
}

app.get(
  '/api/admin/export/pdf',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const groups = await Group.find().lean();

      const allLeaders = await Member.find({ isLeader: true }).select('regNo name group').lean();
      const leadersByGroup = {};
      for (const l of allLeaders) {
        leadersByGroup[String(l.group)] = { regNo: l.regNo, name: l.name };
      }

      groups.sort((a, b) =>
        String(a.name || '').toLowerCase().localeCompare(String(b.name || '').toLowerCase())
      );

      const maxGroupMembers = await getMaxGroupMembers();

      const groupsWithMembers = [];
      for (const g of groups) {
        const members = await Member.find({ group: g._id })
          .sort({ isLeader: -1, createdAt: 1, _id: 1 })
          .select('regNo name phone isLeader createdAt')
          .lean();
        const leader = leadersByGroup[String(g._id)] || null;
        groupsWithMembers.push({
          id: String(g._id),
          name: g.name,
          memberCount: g.memberCount,
          capacity: maxGroupMembers,
          leaderName: leader ? leader.name : null,
          leaderRegNo: leader ? leader.regNo : null,
          members: members.map((m) => ({
            regNo: m.regNo,
            name: m.name,
            phone: m.phone,
            isLeader: Boolean(m.isLeader),
            createdAt: m.createdAt,
          })),
        });
      }

      const pdfBuffer = await buildGroupsPdf({
        groups: groupsWithMembers,
        reportTitle: 'Complete Group Registry',
        reportSubtitle: `All Physics Education groups and their members (${groupsWithMembers.length} group${groupsWithMembers.length === 1 ? '' : 's'}).`,
        maxGroupMembers,
      });

      const filename = `physics-education-groups-complete-${new Date().toISOString().slice(0, 10)}.pdf`;
      console.log(`[admin] PDF export generated (${groupsWithMembers.length} groups, ${formatBytes(pdfBuffer.length)})`);

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).end(pdfBuffer);
    } catch (pdfErr) {
      console.error('[admin-pdf] ERROR:', pdfErr && pdfErr.stack ? pdfErr.stack : pdfErr);
      throw pdfErr;
    }
  })
);

app.get(
  '/api/admin/export/paid/pdf',
  requireAdmin,
  asyncHandler(async (req, res) => {
    try {
      const paidMembers = await Member.find({ paymentStatus: 'verified' })
        .populate('group', 'name normalizedName')
        .lean();

      paidMembers.sort((a, b) => {
        const ga = (a.group && a.group.name ? a.group.name : '').toLowerCase();
        const gb = (b.group && b.group.name ? b.group.name : '').toLowerCase();
        if (ga < gb) return -1;
        if (ga > gb) return 1;
        const pa = a.paymentVerifiedAt ? new Date(a.paymentVerifiedAt).getTime() : 0;
        const pb = b.paymentVerifiedAt ? new Date(b.paymentVerifiedAt).getTime() : 0;
        if (pa !== pb) return pa - pb;
        return String(a.regNo).localeCompare(String(b.regNo));
      });

      const rows = paidMembers.map((m) => ({
        groupName: m.group ? m.group.name : '',
        regNo: m.regNo,
        name: m.name,
        phone: m.phone,
        mpesaCode: m.mpesaCode || '',
        paymentAmount: m.paymentAmount != null ? m.paymentAmount : null,
        paymentNote: m.paymentNote || '',
        paymentSubmittedAt: m.paymentSubmittedAt || null,
        isLeader: Boolean(m.isLeader),
      }));

      const pdfBuffer = await buildPaidMembersPdf({
        rows,
        reportTitle: 'Verified Payments — Reconciliation Report',
        reportSubtitle: `Only members whose M-Pesa codes have been verified by the admin (${rows.length} record${rows.length === 1 ? '' : 's'}).`,
      });

      const filename = `physics-education-groups-paid-${new Date().toISOString().slice(0, 10)}.pdf`;
      console.log(`[admin] PAID PDF export generated (${rows.length} verified members, ${formatBytes(pdfBuffer.length)})`);

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).end(pdfBuffer);
    } catch (pdfErr) {
      console.error('[admin-paid-pdf] ERROR:', pdfErr && pdfErr.stack ? pdfErr.stack : pdfErr);
      throw pdfErr;
    }
  })
);

app.get(
  '/api/member/export/pdf',
  requireMember,
  asyncHandler(async (req, res) => {
    try {
      const member = await Member.findById(req._session.subjectId);
      if (!member) return fail(res, 'Session invalid.', 'SESSION_INVALID', 401);

      const group = await Group.findById(member.group);
      if (!group) return fail(res, 'Group not found.', 'NOT_FOUND', 404);

      const [members, maxGroupMembers] = await Promise.all([
        Member.find({ group: group._id })
          .sort({ isLeader: -1, createdAt: 1, _id: 1 })
          .select('regNo name phone isLeader createdAt')
          .lean(),
        getMaxGroupMembers(),
      ]);
      const leader = members.find((m) => m.isLeader) || null;

      const pdfBuffer = await buildGroupsPdf({
        groups: [
          {
            id: String(group._id),
            name: group.name,
            memberCount: group.memberCount,
            capacity: maxGroupMembers,
            leaderName: leader ? leader.name : null,
            leaderRegNo: leader ? leader.regNo : null,
            members: members.map((m) => ({
              regNo: m.regNo,
              name: m.name,
              phone: m.phone,
              isLeader: Boolean(m.isLeader),
              createdAt: m.createdAt,
            })),
          },
        ],
        reportTitle: 'Group Member Directory',
        reportSubtitle: `Group roster for "${group.name}".`,
        maxGroupMembers,
      });

      const safeName = group.name.replace(/[^A-Za-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '') || 'group';
      const filename = `physics-group-${safeName}-${new Date().toISOString().slice(0, 10)}.pdf`;
      console.log(`[member] PDF export generated for group "${group.name}" (${formatBytes(pdfBuffer.length)})`);

      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
      res.setHeader('Content-Length', String(pdfBuffer.length));
      res.setHeader('Cache-Control', 'no-store');
      return res.status(200).end(pdfBuffer);
    } catch (pdfErr) {
      console.error('[member-pdf] ERROR:', pdfErr && pdfErr.stack ? pdfErr.stack : pdfErr);
      throw pdfErr;
    }
  })
);

/* ============================================================================
 * SECTION 14 — SSE ENDPOINT
 * ============================================================================
 *
 * Admin dashboard subscribes here for live updates. The connection stays
 * open; we send a heartbeat every 25 seconds. Requires an admin session.
 * ========================================================================== */

app.get('/api/admin/events', requireAdmin, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (res.flushHeaders) res.flushHeaders();

  // Greeting event so the client knows the stream is live.
  res.write(`event: hello\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`);

  sseClients.add(res);

  req.on('close', () => {
    sseClients.delete(res);
    try { res.end(); } catch (_) { /* ignore */ }
  });
});

/* ============================================================================
 * SECTION 15 — STATIC FILES & PAGE ROUTES
 * ============================================================================
 *
 * Serves the /public directory and routes pretty URLs to the correct HTML
 * files. HTML files are always revalidated (no long cache) so deploys are
 * picked up immediately.
 * ========================================================================== */

const publicDir = path.join(__dirname, 'public');

app.use(
  express.static(publicDir, {
    index: false,
    maxAge: IS_PROD ? '1h' : 0,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    },
  })
);

app.get('/', (req, res) => res.sendFile(path.join(publicDir, 'index.html')));

app.get(
  ['/member', '/member-login', '/member-login.html', '/member-dashboard', '/member-dashboard.html'],
  (req, res) => res.sendFile(path.join(publicDir, 'member.html'))
);

app.get(
  ['/admin', '/admin-login', '/admin-login.html', '/admin-dashboard', '/admin-dashboard.html', '/admin-group'],
  (req, res) => res.sendFile(path.join(publicDir, 'admin.html'))
);

/* ============================================================================
 * SECTION 16 — 404 & ERROR HANDLERS
 * ============================================================================
 *
 * API 404s return JSON. Non-API 404s serve 404.html if available.
 * The error handler strips stack traces and Mongo internals from user
 * responses and logs the full error server-side.
 * ========================================================================== */

app.use('/api', (req, res) => fail(res, 'Endpoint not found.', 'NOT_FOUND', 404));

app.use((req, res) => {
  const notFoundPath = path.join(publicDir, '404.html');
  if (fs.existsSync(notFoundPath)) return res.status(404).sendFile(notFoundPath);
  return res.status(404).send('Not found');
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  // Known application error.
  if (err instanceof AppError) {
    console.warn(`[error] ${err.code}: ${err.message}`);
    return fail(res, err.message, err.code, err.status);
  }

  // Mongoose validation error.
  if (err && err.name === 'ValidationError') {
    const first = Object.values(err.errors)[0];
    console.warn('[error] ValidationError:', first ? first.message : err.message);
    return fail(res, first ? first.message : 'Validation error.', 'VALIDATION', 400);
  }

  // Duplicate key.
  if (err && err.code === 11000) {
    console.warn('[error] Duplicate key:', JSON.stringify(err.keyPattern || {}));
    const keys = err.keyPattern || {};
    if (keys.regNo) return fail(res, 'This registration number already exists.', 'DUPLICATE_REGNO', 409);
    if (keys.deviceId) return fail(res, 'This device has already been used.', 'DEVICE_USED', 409);
    if (keys.normalizedName) return fail(res, 'A group with that name already exists.', 'DUPLICATE_GROUP', 409);
    if (keys.mpesaCode) return fail(res, 'This M-Pesa code has already been used.', 'DUPLICATE_MPESA_CODE', 409);
    return fail(res, 'Duplicate value.', 'DUPLICATE', 409);
  }

  // Bad ObjectId.
  if (err && err.name === 'CastError') {
    return fail(res, 'Invalid identifier.', 'INVALID_ID', 400);
  }

  // Unknown error — log the full stack server-side, respond generically.
  console.error('[error] Unhandled:', err && err.stack ? err.stack : err);
  return fail(
    res,
    'We could not complete your request. Please contact the Administrator.',
    'SERVER_ERROR',
    500
  );
});

/* ============================================================================
 * SECTION 17 — SERVER STARTUP & SHUTDOWN
 * ============================================================================
 *
 * Binds to 0.0.0.0:$PORT (required by Render). Handles SIGTERM/SIGINT
 * gracefully by closing the HTTP server, ending SSE streams, and closing
 * the MongoDB connection.
 * ========================================================================== */

let httpServer = null;

/**
 * Start the HTTP server.
 */
async function start() {
  try {
    await connectDatabase();

    httpServer = http.createServer(app);

    httpServer.listen(PORT, '0.0.0.0', () => {
      console.log(`[boot] HTTP server listening on 0.0.0.0:${PORT}`);
      console.log(`[boot] Admin bootstrap username: ${ADMIN_USERNAME}`);
    });

    httpServer.on('error', (err) => console.error('[boot] HTTP server error:', err.message));
  } catch (err) {
    console.error('[boot] Startup failed:', err.message);
    process.exit(1);
  }
}

/**
 * Graceful shutdown.
 * @param {string} signal
 */
async function shutdown(signal) {
  console.log(`\n[shutdown] Received ${signal}. Closing gracefully...`);
  try {
    if (httpServer) {
      await new Promise((resolve) => httpServer.close(resolve));
      console.log('[shutdown] HTTP server closed.');
    }
    for (const res of sseClients) {
      try { res.end(); } catch (_) { /* ignore */ }
    }
    sseClients.clear();
    await disconnectDatabase();
  } catch (err) {
    console.error('[shutdown] Error during shutdown:', err.message);
  } finally {
    process.exit(0);
  }
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
process.on('unhandledRejection', (reason) => console.error('[process] Unhandled rejection:', reason));
process.on('uncaughtException', (err) => console.error('[process] Uncaught exception:', err && err.stack ? err.stack : err));

if (require.main === module) {
  start();
}

module.exports = { app, start, CONFIG };

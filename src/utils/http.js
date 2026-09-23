'use strict';

/**
 * Tiny HTTP helper built on the global `fetch` (Node >= 18).
 * Adds a per-request timeout and never throws: failures resolve to null so
 * enrichment can degrade gracefully when offline or rate-limited.
 */

/**
 * @param {string} url
 * @param {{ timeout?: number, headers?: object, body?: any }} [options]
 *   `body`: sent as a JSON POST when present.
 * @returns {Promise<{ ok: boolean, status: number, json: any, headers: Headers }|null>}
 */
async function fetchJson(url, { timeout = 8000, headers = {}, body } = {}) {
  if (typeof fetch !== 'function') return null;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);

  try {
    const init = {
      headers: { Accept: 'application/json', ...headers },
      signal: controller.signal,
      redirect: 'follow',
    };
    if (body !== undefined) {
      init.method = 'POST';
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    const res = await fetch(url, init);
    let json = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return { ok: res.ok, status: res.status, json, headers: res.headers };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Runs an async mapper over items with bounded concurrency.
 * @template T, R
 * @param {T[]} items
 * @param {(item: T, index: number) => Promise<R>} mapper
 * @param {number} concurrency
 * @returns {Promise<R[]>}
 */
async function mapLimit(items, mapper, concurrency = 8) {
  const results = new Array(items.length);
  let cursor = 0;

  const workers = new Array(Math.min(concurrency, items.length)).fill(0).map(async () => {
    while (cursor < items.length) {
      const index = cursor++;
      results[index] = await mapper(items[index], index);
    }
  });

  await Promise.all(workers);
  return results;
}

module.exports = { fetchJson, mapLimit };

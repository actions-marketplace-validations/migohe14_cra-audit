'use strict';

/**
 * Minimal YAML parser covering the subset used by `pnpm-lock.yaml` and
 * Yarn Berry (v2+) lockfiles: indentation-based maps and sequences, inline
 * flow collections (`{ ... }` and `[ ... ]`) and single/double quoted scalars.
 *
 * It intentionally does NOT support anchors, aliases, block scalars (`|` / `>`),
 * multi-document streams or complex keys. cra-audit ships with zero runtime
 * dependencies, so this keeps us from pulling in a full YAML library just to
 * read a lockfile.
 *
 * @param {string} text
 * @returns {object|Array|null}
 */
function parseYaml(text) {
  const lines = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const withoutComment = stripComment(raw);
    if (withoutComment.trim() === '') continue;
    const trimmedLeft = withoutComment.replace(/^ +/, '');
    const indent = withoutComment.length - trimmedLeft.length;
    lines.push({ indent, content: trimmedLeft.replace(/\s+$/, '') });
  }

  const state = { lines, pos: 0 };
  if (state.lines.length === 0) return {};
  return parseNode(state, state.lines[0].indent);
}

/** Removes an unquoted `#` comment, preserving `#` inside quoted scalars. */
function stripComment(line) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === '#' && !inSingle && !inDouble && (i === 0 || /\s/.test(line[i - 1]))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function parseNode(state, indent) {
  const line = state.lines[state.pos];
  if (line.content === '-' || line.content.startsWith('- ')) {
    return parseSequence(state, indent);
  }
  return parseMap(state, indent);
}

function parseMap(state, indent) {
  const map = {};
  while (state.pos < state.lines.length) {
    const line = state.lines[state.pos];
    if (line.indent < indent) break;
    if (line.indent > indent) { state.pos++; continue; }

    const { key, rest } = splitKey(line.content);
    if (key === null) { state.pos++; continue; }
    state.pos++;

    if (rest !== '') {
      map[key] = parseScalarOrFlow(rest);
    } else if (state.pos < state.lines.length && state.lines[state.pos].indent > indent) {
      map[key] = parseNode(state, state.lines[state.pos].indent);
    } else {
      map[key] = null;
    }
  }
  return map;
}

function parseSequence(state, indent) {
  const arr = [];
  while (state.pos < state.lines.length) {
    const line = state.lines[state.pos];
    if (line.indent < indent) break;
    if (line.indent > indent) { state.pos++; continue; }
    if (line.content !== '-' && !line.content.startsWith('- ')) break;

    const after = line.content === '-' ? '' : line.content.slice(2);
    state.pos++;
    if (after === '') {
      if (state.pos < state.lines.length && state.lines[state.pos].indent > indent) {
        arr.push(parseNode(state, state.lines[state.pos].indent));
      } else {
        arr.push(null);
      }
    } else {
      arr.push(parseScalarOrFlow(after));
    }
  }
  return arr;
}

/** Splits `key: value` honoring quoted keys; returns { key, rest }. */
function splitKey(content) {
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (ch === "'" && !inDouble) inSingle = !inSingle;
    else if (ch === '"' && !inSingle) inDouble = !inDouble;
    else if (ch === ':' && !inSingle && !inDouble) {
      const next = content[i + 1];
      if (next === undefined || next === ' ') {
        return { key: unquote(content.slice(0, i).trim()), rest: content.slice(i + 1).trim() };
      }
    }
  }
  return { key: null, rest: '' };
}

function parseScalarOrFlow(str) {
  const s = str.trim();
  if (s.startsWith('{') || s.startsWith('[')) {
    return parseFlow(s);
  }
  return parseScalar(s);
}

function parseScalar(s) {
  if (s === '' || s === '~' || s === 'null') return null;
  if (s === 'true') return true;
  if (s === 'false') return false;
  return unquote(s);
}

function unquote(s) {
  const t = s.trim();
  if (t.length >= 2) {
    if (t[0] === '"' && t[t.length - 1] === '"') {
      return t.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    if (t[0] === "'" && t[t.length - 1] === "'") {
      return t.slice(1, -1).replace(/''/g, "'");
    }
  }
  return t;
}

/** Parses an inline flow collection: `{ a: b, c: [d, e] }`. */
function parseFlow(s) {
  const ctx = { s, i: 0 };
  return parseFlowValue(ctx);
}

function parseFlowValue(ctx) {
  skipWs(ctx);
  const ch = ctx.s[ctx.i];
  if (ch === '{') return parseFlowMap(ctx);
  if (ch === '[') return parseFlowSeq(ctx);
  return parseScalar(readFlowScalar(ctx));
}

function parseFlowMap(ctx) {
  const map = {};
  ctx.i++; // consume '{'
  skipWs(ctx);
  if (ctx.s[ctx.i] === '}') { ctx.i++; return map; }
  while (ctx.i < ctx.s.length) {
    skipWs(ctx);
    const key = unquote(readFlowKey(ctx));
    skipWs(ctx);
    if (ctx.s[ctx.i] === ':') ctx.i++;
    const value = parseFlowValue(ctx);
    map[key] = value;
    skipWs(ctx);
    if (ctx.s[ctx.i] === ',') { ctx.i++; continue; }
    if (ctx.s[ctx.i] === '}') { ctx.i++; break; }
    break;
  }
  return map;
}

function parseFlowSeq(ctx) {
  const arr = [];
  ctx.i++; // consume '['
  skipWs(ctx);
  if (ctx.s[ctx.i] === ']') { ctx.i++; return arr; }
  while (ctx.i < ctx.s.length) {
    arr.push(parseFlowValue(ctx));
    skipWs(ctx);
    if (ctx.s[ctx.i] === ',') { ctx.i++; continue; }
    if (ctx.s[ctx.i] === ']') { ctx.i++; break; }
    break;
  }
  return arr;
}

function readFlowKey(ctx) {
  return readUntil(ctx, [':', ',', '}']);
}

function readFlowScalar(ctx) {
  return readUntil(ctx, [',', '}', ']']);
}

/** Reads a quoted or bare token until one of the stop characters at top level. */
function readUntil(ctx, stops) {
  skipWs(ctx);
  const start = ctx.i;
  const quote = ctx.s[ctx.i];
  if (quote === '"' || quote === "'") {
    ctx.i++;
    while (ctx.i < ctx.s.length) {
      const ch = ctx.s[ctx.i];
      if (ch === '\\' && quote === '"') { ctx.i += 2; continue; }
      if (ch === quote) { ctx.i++; break; }
      ctx.i++;
    }
    return ctx.s.slice(start, ctx.i).trim();
  }
  while (ctx.i < ctx.s.length && !stops.includes(ctx.s[ctx.i])) ctx.i++;
  return ctx.s.slice(start, ctx.i).trim();
}

function skipWs(ctx) {
  while (ctx.i < ctx.s.length && /\s/.test(ctx.s[ctx.i])) ctx.i++;
}

module.exports = { parseYaml };

/*
 * Copyright (c) 2026 Tabith LLC.
 * Use of this source code is governed by the Business Source License 1.1
 * included in the LICENSE file at the root of this repository. As of the
 * Change Date listed there, the work is available under MPL 2.0.
 * SPDX-License-Identifier: BUSL-1.1
 *
 * Timeline for the example-workflow animation.
 *
 * There is no clock in here. Every animated property is a list of keyframes
 * ([time, value, easing]) and seek(t) evaluates all of them for second t. That
 * makes a frame a pure function of t, so scripts/render-animation.py can step
 * through time exactly and identical frames collapse in the GIF.
 *
 * To re-time a beat, edit the storyboard() section; scene start times are the
 * capital letters at its top and every beat is written relative to one.
 */
'use strict';

// ============================================================ engine

const EASE = {
  lin: (p) => p,
  io: (p) => (p < 0.5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2),
  out: (p) => 1 - Math.pow(1 - p, 3),
  in: (p) => p * p * p,
};

const tracks = new Map(); // element -> Map(prop -> [[t, value, ease], ...])

function byId(id) {
  const e = document.getElementById(id);
  if (!e) throw new Error(`animation: no element #${id}`);
  return e;
}
const el = (x) => (typeof x === 'string' ? byId(x) : x);

function key(target, prop, ...keys) {
  const e = el(target);
  let m = tracks.get(e);
  if (!m) tracks.set(e, (m = new Map()));
  let ks = m.get(prop);
  if (!ks) m.set(prop, (ks = []));
  ks.push(...keys);
}

function valueAt(ks, t) {
  if (t <= ks[0][0]) return ks[0][1];
  for (let i = 1; i < ks.length; i++) {
    const [t1, v1, ease] = ks[i];
    if (t < t1) {
      const [t0, v0] = ks[i - 1];
      if (typeof v0 !== 'number' || typeof v1 !== 'number' || t1 === t0) return v0;
      return v0 + (v1 - v0) * EASE[ease || 'io']((t - t0) / (t1 - t0));
    }
  }
  return ks[ks.length - 1][1];
}

function apply(e, v) {
  if ('o' in v || 'dim' in v) {
    const o = ('o' in v ? v.o : 1) * (1 - 0.6 * ('dim' in v ? v.dim : 0));
    e.style.opacity = o.toFixed(3);
    e.style.visibility = o <= 0.002 ? 'hidden' : '';
  }
  if ('x' in v || 'y' in v || 's' in v) {
    e.style.transform = `translate(${(v.x || 0).toFixed(2)}px, ${(v.y || 0).toFixed(2)}px) scale(${(v.s ?? 1).toFixed(4)})`;
  }
  if ('hl' in v) e.style.setProperty('--hl', v.hl.toFixed(3));
  if ('reveal' in v) {
    // Monospace typewriter: clip to a whole number of characters.
    const n = +e.dataset.cols;
    const k = Math.round(v.reveal * n);
    e.style.clipPath = k >= n ? '' : `inset(-3px ${(100 - (100 * k) / n).toFixed(3)}% -3px 0)`;
  }
  if ('chars' in v) {
    const s = e._full.slice(0, Math.round(v.chars));
    if (e.textContent !== s) e.textContent = s;
  }
  if ('p' in v) {
    const d = (e._rev ? 1 - v.p : v.p) * e._len;
    const pt = e._path.getPointAtLength(d);
    e.setAttribute('transform', `translate(${pt.x.toFixed(2)} ${pt.y.toFixed(2)})`);
  }
  if ('text' in v && e.textContent !== v.text) e.textContent = v.text;
  for (const k in v) if (k[0] === '.') e.classList.toggle(k.slice(1), !!v[k]);
}

function seek(t) {
  for (const [e, m] of tracks) {
    const v = {};
    for (const [p, ks] of m) v[p] = valueAt(ks, t);
    apply(e, v);
  }
}

function finalize() {
  for (const m of tracks.values()) for (const ks of m.values()) ks.sort((a, b) => a[0] - b[0]);
}

// ============================================================ helpers

const F = 0.25; // default fade

const COLOR = {
  human: '#60a5fa',
  agent: '#b18cff',
  core: '#2dd4bf',
  ok: '#4ade80',
  danger: '#f87171',
  secret: '#fbbf24',
  plain: '#dfe6f2',
};

/** Visible from a to b (b = null: stays). */
function show(id, a, b, f = F) {
  const ks = [[0, 0], [a, 0], [a + f, 1, 'out']];
  if (b != null) ks.push([b, 1], [b + f, 0, 'in']);
  key(id, 'o', ...ks);
}

/** Visible from t = 0 until b. */
function showFromStart(id, b, f = F) {
  key(id, 'o', [0, 1], [b, 1], [b + f, 0, 'in']);
}

/** Fade + slide up into place at t. */
function rise(id, t, dy = 5, d = 0.3) {
  key(id, 'o', [0, 0], [t, 0], [t + d, 1, 'out']);
  key(id, 'y', [0, dy], [t, dy], [t + d, 0, 'out']);
}

/** Caption: slides in at a, fully gone by b (so neighbours never overlap). */
function caption(id, a, b) {
  key(id, 'o', [0, 0], [a, 0], [a + 0.28, 1, 'out'], [b - 0.18, 1], [b, 0, 'in']);
  key(id, 'y', [0, 5], [a, 5], [a + 0.28, 0, 'out']);
}

/** Highlight ring on a card or link over [a, b]. Spans must not overlap per element. */
function hl(id, a, b) {
  key(id, 'hl', [0, 0], [a, 0], [a + 0.2, 1, 'out'], [b, 1], [b + 0.4, 0, 'in']);
}

function flag(id, cls, ...pairs) {
  key(id, `.${cls}`, [0, false], ...pairs);
}

/** Card that appears (slight scale-up) and disappears over each [a, b] span. */
function spawn(id, spans) {
  const o = [[0, 0]];
  const s = [[0, 0.94]];
  for (const [a, b] of spans) {
    o.push([a, 0], [a + 0.3, 1, 'out'], [b, 1], [b + 0.3, 0, 'in']);
    s.push([a, 0.94], [a + 0.3, 1, 'out'], [b + 0.3, 1], [b + 0.31, 0.94]);
  }
  key(id, 'o', ...o);
  key(id, 's', ...s);
}

/** Monospace typewriter (clip by whole characters). */
function typeLine(id, t, dur) {
  const e = byId(id);
  e.dataset.cols = String(e.textContent.length);
  key(e, 'o', [0, 0], [t, 0], [t + 0.01, 1]);
  key(e, 'reveal', [0, 0], [t, 0], [t + dur, 1, 'lin']);
}

/** Plain-text typewriter (text node grows). */
function typeChars(id, t, dur) {
  const e = byId(id);
  e._full = e.textContent;
  key(e, 'chars', [0, 0], [t, 0], [t + dur, e._full.length, 'lin']);
}

// Lines of the agent's-view transcript, recorded so it can auto-scroll.
const viewLog = [];
function vtype(id, t, dur) {
  typeLine(id, t, dur);
  viewLog.push([t, byId(id)]);
}
function vline(id, t) {
  rise(id, t, 4, 0.3);
  viewLog.push([t, byId(id)]);
}

function buildScroll() {
  const sc = byId('view-scroll');
  const H = sc.parentElement.clientHeight;
  const ks = [[0, 0]];
  let cur = 0;
  for (const [t, e] of [...viewLog].sort((a, b) => a[0] - b[0])) {
    const need = Math.max(0, e.offsetTop + e.offsetHeight - H + 1);
    if (need <= cur + 0.5) continue;
    const last = ks[ks.length - 1];
    if (last[0] > t - 0.05) {
      last[0] = Math.max(last[0], t + 0.3);
      last[1] = -need;
    } else {
      ks.push([t - 0.05, -cur], [t + 0.3, -need, 'out']);
    }
    cur = need;
  }
  key(sc, 'y', ...ks);
}

// --- packets travelling along wires -------------------------------------

const NS = 'http://www.w3.org/2000/svg';
const SHAPES = {
  dot: (c) =>
    `<circle r="8.5" fill="${c}" opacity="0.18"/>` +
    `<circle r="4.3" fill="${c}" stroke="#0a0e17" stroke-width="1.8"/>`,
  small: (c) => `<circle r="3.2" fill="${c}" stroke="#0a0e17" stroke-width="1.4"/>`,
  // The wrapped secret: amber capsule with a lock.
  capsule: () =>
    `<circle r="16" fill="#fbbf24" opacity="0.16"/>` +
    `<rect x="-14" y="-8.5" width="28" height="17" rx="8.5" fill="#fbbf24" stroke="#0a0e17" stroke-width="1.5"/>` +
    `<g transform="translate(-6 -6.6) scale(0.5)" fill="none" stroke="#2a1d02" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round">` +
    `<rect x="5" y="10.5" width="14" height="10" rx="2"/><path d="M8.5 10.5V7.5a3.5 3.5 0 0 1 7 0v3"/></g>`,
  // The unwrapped secret: a file.
  file: () =>
    `<circle r="13" fill="#fbbf24" opacity="0.16"/>` +
    `<path d="M-6 -8 h7.5 l4.5 4.5 v11.5 h-12 z" fill="#fbbf24" stroke="#0a0e17" stroke-width="1.3" stroke-linejoin="round"/>` +
    `<path d="M1.5 -8 v4.5 h4.5" fill="none" stroke="#7a5a0a" stroke-width="1.3" stroke-linejoin="round"/>`,
};

/**
 * Send a packet along an SVG path.
 *   t, dur   start time and travel time
 *   color    fill (dot shapes)
 *   rev      travel the path backwards
 *   to       stop short (fraction of the path)
 *   pre      appear this long before moving (sits at the start)
 *   hold     stay visible this long after arriving
 */
function packet(kind, path, t, dur, o = {}) {
  const g = document.createElementNS(NS, 'g');
  g.innerHTML = SHAPES[kind](o.color);
  byId('packets').appendChild(g);
  g._path = byId(path);
  g._len = g._path.getTotalLength();
  g._rev = !!o.rev;
  const to = o.to ?? 1;
  const pre = o.pre ?? 0;
  const hold = o.hold ?? 0;
  const fade = o.fade ?? 0.12;
  key(g, 'p', [0, 0], [t, 0], [t + dur, to, o.ease || 'io']);
  key(g, 'o', [0, 0], [t - pre - 0.08, 0], [t - pre, 1], [t + dur + hold, 1], [t + dur + hold + fade, 0]);
  return g;
}

/** Expanding ring, e.g. the capsule opening. */
function burst(x, y, t, color = COLOR.secret) {
  const c = document.createElementNS(NS, 'circle');
  c.setAttribute('cx', x);
  c.setAttribute('cy', y);
  c.setAttribute('r', 10);
  c.setAttribute('fill', 'none');
  c.setAttribute('stroke', color);
  c.setAttribute('stroke-width', 2);
  c.style.transformBox = 'fill-box';
  c.style.transformOrigin = 'center';
  byId('packets').appendChild(c);
  key(c, 's', [0, 0.5], [t, 0.5], [t + 0.5, 2.1, 'out']);
  key(c, 'o', [0, 0], [t, 0], [t + 0.02, 0.9], [t + 0.5, 0, 'lin']);
}

/** FIDO2 touch ring on the human card. */
function ring(id, t) {
  key(id, 's', [0, 0.7], [t, 0.7], [t + 0.8, 1.9, 'out']);
  key(id, 'o', [0, 0], [t, 0], [t + 0.02, 0.9], [t + 0.8, 0, 'lin']);
}

/** Executor status comes back from list_executors(). */
function status(card, label, text, cls, t) {
  flag(card, cls, [t, true]);
  key(label, 'text', [0, '-'], [t, text]);
  hl(card, t, t + 0.5);
}

// ============================================================ storyboard

const CARDS = ['c-human', 'c-agent', 'c-core', 'c-net', 'c-sto', 'c-bak', 'c-nas', 'c-dr'];

/** Dim every card not named in the current focus set. */
function focus(states) {
  for (const id of CARDS) {
    const first = states[0][1].includes(id) ? 0 : 1;
    const ks = [[0, first]];
    let prev = first;
    for (const [t, ids] of states.slice(1)) {
      const v = ids.includes(id) ? 0 : 1;
      ks.push([t, prev], [t + 0.3, v]);
      prev = v;
    }
    key(id, 'dim', ...ks);
  }
}

function storyboard() {
  // Scene starts, in seconds.
  const A = 3.6; //          authorize
  const B = A + 8.0; //      step 1  discover
  const C = B + 4.8; //      step 2  secrets
  const D = C + 5.6; //      step 3  probe (fails)
  const E = D + 7.6; //      step 4  escalate: the secret's journey
  const G5 = E + 22.4; //    step 5  remediate
  const G6 = G5 + 7.8; //    step 6  audit
  const H = G6 + 5.4; //     the agent's report
  const I = H + 6.6; //      end card
  const END = I + 4.6;

  // --- title card: fully visible on frame 0 (GitHub shows it while loading),
  // and faded back in at the end so the loop is seamless.
  key('ov-title', 'o', [0, 1], [A - 0.3, 1], [A + 0.05, 0, 'in'], [END - 0.4, 0], [END, 1, 'out']);

  // --- chapter tracker
  const starts = [A, B, C, D, E, G5, G6, H];
  for (let i = 0; i < 7; i++) {
    flag(`ch${i}`, 'active', [starts[i], true], [starts[i + 1], false]);
    flag(`ch${i}`, 'done', [starts[i + 1], true]);
  }

  focus([
    [A, ['c-human', 'c-agent', 'c-core']],
    [B, ['c-agent', 'c-core', 'c-net', 'c-sto', 'c-bak']],
    [C, ['c-agent', 'c-core']],
    [D, ['c-agent', 'c-core', 'c-net', 'c-nas']],
    [E, ['c-agent', 'c-core', 'c-sto', 'c-nas']],
    [G5, ['c-agent', 'c-core', 'c-sto', 'c-nas', 'c-dr']],
    [G6, ['c-agent', 'c-core']],
    [H, ['c-human', 'c-agent']],
  ]);

  // Links that carry the secret glow amber.
  for (const id of ['l-core-sto', 'l-sto-in']) byId(id).style.setProperty('--lc', COLOR.secret);

  // Transcript entries dim once the next one starts.
  const entryStart = { v0: A + 5.2, v1: B + 0.3, v2: C + 0.3, v3: D + 0.3, v4: E + 0.3, v5: G5 + 0.3, v6: G6 + 0.3 };
  const ids = Object.keys(entryStart);
  ids.forEach((id, i) => {
    if (ids[i + 1]) flag(id, 'old', [entryStart[ids[i + 1]], true]);
  });

  // Audit slots fill as each command executes (attributed to jreyes).
  const audit = (n, t) => flag(`slot${n}`, 'on', [t, true]);

  // ------------------------------------------------ authorize
  caption('cap-a0', A + 0.1, A + 4.3);
  caption('cap-a1', A + 4.3, B);
  show('b-auth', A + 0.3, B - 0.25);

  hl('c-human', A + 0.4, A + 2.9);
  ring('ring1', A + 0.7);
  ring('ring2', A + 1.05);
  packet('dot', 'l-human-core', A + 1.5, 0.5, { color: COLOR.human });
  hl('c-core', A + 2.0, A + 3.5);
  showFromStart('sess-none', A + 2.0, 0.2);
  rise('sess-on', A + 2.1);
  rise('ba1', A + 2.0);
  rise('ba2', A + 2.4);
  packet('dot', 'l-agent-core', A + 2.6, 0.5, { color: COLOR.core, rev: true });
  hl('c-agent', A + 3.1, A + 3.7);
  rise('agent-sess', A + 3.1, 3);
  rise('ba3', A + 3.2);

  // the one sentence
  hl('c-human', A + 4.4, A + 5.6);
  packet('dot', 'l-human-agent', A + 4.6, 0.6, { color: COLOR.human });
  hl('c-agent', A + 5.2, A + 7.3);
  rise('v0a', A + 5.2, 3, 0.2);
  viewLog.push([A + 5.2, byId('v0a')]);
  typeChars('v0b', A + 5.3, 1.4);

  // ------------------------------------------------ step 1: discover
  caption('cap-1', B, C);
  show('b-s1', B + 0.2, C - 0.25);
  vtype('v1a', B + 0.3, 0.35);
  packet('dot', 'l-agent-core', B + 0.7, 0.45, { color: COLOR.agent });
  hl('c-core', B + 1.1, B + 2.1);
  rise('b1a', B + 1.2);
  rise('b1b', B + 1.3);
  rise('b1c', B + 1.4);
  rise('b1d', B + 1.9);
  packet('dot', 'l-agent-core', B + 1.5, 0.45, { color: COLOR.core, rev: true });
  status('c-sto', 'st-sto', 'ONLINE', 'on', B + 1.65);
  status('c-net', 'st-net', 'ONLINE', 'on', B + 1.75);
  status('c-bak', 'st-bak', 'OFFLINE', 'off', B + 1.85);
  vline('v1b', B + 1.95);
  vline('v1c', B + 2.05);
  vline('v1d', B + 2.15);

  // ------------------------------------------------ step 2: secrets
  caption('cap-2', C, D);
  show('b-s2', C + 0.2, D - 0.25);
  vtype('v2a', C + 0.3, 0.35);
  packet('dot', 'l-agent-core', C + 0.7, 0.45, { color: COLOR.agent });
  hl('c-core', C + 1.1, C + 2.1);
  rise('b2a', C + 1.2);
  rise('b2b', C + 1.3);
  rise('b2c', C + 1.7);
  rise('b2d', C + 2.1);
  packet('dot', 'l-agent-core', C + 1.5, 0.45, { color: COLOR.core, rev: true });
  vline('v2b', C + 1.95);
  vline('v2c', C + 2.05);
  vline('v2d', C + 2.15);
  // only one of the two will be requested
  flag('vr-nas', 'pick', [C + 3.2, true]);
  key('vr-mon', 'o', [0, 1], [C + 3.2, 1], [C + 3.5, 0.4]);
  flag('v2c', 'pickln', [C + 3.2, true]);
  flag('v2d', 'dimln', [C + 3.2, true]);

  // ------------------------------------------------ step 3: probe from network-01 (fails)
  caption('cap-3', D, E);
  show('b-s3', D + 0.2, E - 0.25);
  vtype('v3a', D + 0.3, 0.45);
  vtype('v3b', D + 0.75, 0.35);
  vtype('v3c', D + 1.1, 0.2);
  packet('dot', 'l-agent-core', D + 1.35, 0.45, { color: COLOR.agent });
  hl('c-core', D + 1.75, D + 2.35);
  packet('dot', 'l-core-net', D + 1.95, 0.45, { color: COLOR.core });
  hl('c-net', D + 2.35, D + 6.0);
  spawn('sbx-net', [[D + 2.45, D + 6.2]]);
  packet('dot', 'm-net-sbx', D + 2.6, 0.3, { color: COLOR.plain });
  typeLine('b3a', D + 2.8, 0.6);
  packet('dot', 'm-net-out', D + 3.4, 0.55, { color: COLOR.plain, to: 0.5, hold: 0.25 });
  flag('l-net-nas', 'fail', [D + 3.95, true]);
  key('xmark', 'o', [0, 0], [D + 3.95, 0], [D + 4.15, 1]);
  rise('b3b', D + 4.1);
  rise('b3c', D + 4.5);
  rise('b3d', D + 4.85);
  packet('dot', 'm-net-sbx', D + 4.5, 0.3, { color: COLOR.danger, rev: true });
  packet('dot', 'l-core-net', D + 4.85, 0.4, { color: COLOR.danger, rev: true });
  hl('c-core', D + 5.2, D + 5.7);
  audit(1, D + 5.25);
  packet('dot', 'l-agent-core', D + 5.3, 0.4, { color: COLOR.danger, rev: true });
  vline('v3d', D + 5.75);
  vline('v3e', D + 5.85);

  // ------------------------------------------------ step 4: escalate to storage-01
  caption('cap-4a', E, E + 3.6);
  caption('cap-4b', E + 3.6, E + 7.4);
  caption('cap-4c', E + 7.4, E + 11.2);
  caption('cap-4d', E + 11.2, E + 14.8);
  caption('cap-4e', E + 14.8, E + 18.6);
  caption('cap-4f', E + 18.6, G5);
  show('b-s4', E + 0.2, G5 - 0.25);

  vtype('v4a', E + 0.3, 0.45);
  vtype('v4b', E + 0.75, 0.5);
  vtype('v4c', E + 1.25, 0.45);
  packet('dot', 'l-agent-core', E + 1.75, 0.45, { color: COLOR.agent });
  hl('c-core', E + 2.15, E + 5.8);

  // vault -> executor host, wrapped; the agent is not on this path
  packet('capsule', 'p-sec1', E + 4.1, 1.4, { pre: 0.35, hold: 2.4, fade: 0.2 });
  hl('l-core-sto', E + 4.2, E + 5.4);
  hl('c-sto', E + 5.3, E + 21.2);

  // unwrapped host-side into tmpfs, exposed inside the sandbox
  spawn('sbx-sto', [[E + 7.5, E + 21.5], [G5 + 3.0, G5 + 7.2]]);
  burst(590, 166, E + 7.9);
  packet('file', 'p-sec2', E + 7.95, 0.6, { fade: 0.15 });
  hl('l-sto-in', E + 7.95, E + 8.55);
  show('sfile', E + 8.5, E + 21.5, 0.2);
  key('sbx-sto-sub', 'o', [0, 1], [E + 8.4, 1], [E + 8.55, 0], [G5 + 7.5, 0], [G5 + 7.6, 1]);
  rise('b4a', E + 8.3);
  typeLine('b4b', E + 8.9, 0.7);
  packet('dot', 'm-sto-out', E + 9.6, 0.45, { color: COLOR.ok });
  flag('l-sto-nas', 'ok', [E + 10.05, true]);
  hl('c-nas', E + 10.05, E + 12.6);
  showFromStart('nas-st0', E + 10.1, 0.2);
  show('nas-st1', E + 10.2, G5 + 5.0, 0.25);

  // the output comes back carrying the echoed credential
  packet('dot', 'm-sto-out', E + 10.9, 0.45, { color: COLOR.danger, rev: true });
  rise('b4c', E + 11.45);
  rise('b4d', E + 11.65);
  key('leak-tag', 'o', [0, 0], [E + 12.3, 0], [E + 12.6, 1], [E + 15.4, 1], [E + 15.6, 0]);

  // Stage 1: the executor's filter
  key('scan', 'o', [0, 0], [E + 15.0, 0], [E + 15.1, 1], [E + 16.0, 1], [E + 16.15, 0]);
  key('scan', 'x', [0, 0], [E + 15.0, 0], [E + 16.0, 430]);
  key('leak-raw', 'o', [0, 1], [E + 15.45, 1], [E + 15.65, 0]);
  key('leak-masked', 'o', [0, 0], [E + 15.45, 0], [E + 15.65, 1]);
  rise('b4e', E + 16.1);

  // Stage 2: raw bytes to the core for the definitive re-screen; verdict back
  packet('dot', 'l-core-sto', E + 16.4, 0.45, { color: COLOR.plain, rev: true });
  hl('c-core', E + 16.85, E + 17.7);
  packet('dot', 'l-core-sto', E + 17.25, 0.45, { color: COLOR.core });
  rise('b4f', E + 17.75);

  // the masked result reaches the agent
  packet('dot', 'l-core-sto', E + 18.8, 0.4, { color: COLOR.core, rev: true });
  hl('c-core', E + 19.15, E + 19.6);
  audit(2, E + 19.2);
  packet('dot', 'l-agent-core', E + 19.25, 0.4, { color: COLOR.core, rev: true });
  hl('c-agent', E + 19.65, E + 21.9);
  vline('v4d', E + 19.7);
  vline('v4e', E + 19.8);
  vline('v4f', E + 19.9);
  vline('v4g', E + 20.0);
  vline('v4h', E + 20.1);
  flag('v4red', 'glow', [E + 20.2, true], [E + 22.2, false]);

  // the secret file is zeroed when the run ends
  flag('sfile', 'zero', [E + 20.7, true], [G5 + 2.9, false], [G5 + 6.8, true]);
  key('sfile-t', 'text', [0, '…/venya/12 · 0400'], [E + 20.7, 'zeroed'], [G5 + 2.9, '…/venya/12 · 0400'], [G5 + 6.8, 'zeroed']);
  rise('b4g', E + 20.8);

  // ------------------------------------------------ step 5: controlled failover
  caption('cap-5', G5, G6);
  show('b-s5', G5 + 0.2, G6 - 0.25);
  vtype('v5a', G5 + 0.3, 0.45);
  vtype('v5b', G5 + 0.75, 0.45);
  vtype('v5c', G5 + 1.2, 0.45);
  packet('dot', 'l-agent-core', G5 + 1.7, 0.4, { color: COLOR.agent });
  hl('c-core', G5 + 2.05, G5 + 3.0);
  packet('capsule', 'p-sec1', G5 + 2.35, 0.9, { pre: 0.25, hold: 0.25, fade: 0.2 });
  hl('l-core-sto', G5 + 2.45, G5 + 3.2);
  burst(590, 166, G5 + 3.45);
  packet('file', 'p-sec2', G5 + 3.5, 0.45, { fade: 0.15 });
  hl('l-sto-in', G5 + 3.5, G5 + 3.95);
  show('sfile', G5 + 3.9, G5 + 7.2, 0.2);
  rise('b5a', G5 + 3.7);
  typeLine('b5b', G5 + 4.0, 0.6);
  packet('dot', 'm-sto-out', G5 + 4.6, 0.4, { color: COLOR.ok });
  hl('c-nas', G5 + 5.0, G5 + 7.2);
  show('nas-st2', G5 + 5.05, null, 0.25);
  for (let k = 0; k < 5; k++) packet('small', 'l-nas-dr', G5 + 5.1 + k * 0.32, 0.45, { color: COLOR.core });
  flag('l-nas-dr', 'ok', [G5 + 5.1, true]);
  hl('c-dr', G5 + 5.5, G6 - 0.2);
  rise('dr-st1', G5 + 5.5, 3);
  packet('dot', 'm-sto-out', G5 + 5.3, 0.4, { color: COLOR.plain, rev: true });
  rise('b5c', G5 + 5.75);
  rise('b5d', G5 + 5.85);
  rise('b5e', G5 + 5.95);
  packet('dot', 'l-core-sto', G5 + 6.0, 0.35, { color: COLOR.core, rev: true });
  audit(3, G5 + 6.35);
  packet('dot', 'l-agent-core', G5 + 6.4, 0.35, { color: COLOR.core, rev: true });
  hl('c-agent', G5 + 6.75, G5 + 7.6);
  vline('v5d', G5 + 6.8);
  vline('v5e', G5 + 6.9);
  vline('v5f', G5 + 7.0);
  vline('v5g', G5 + 7.1);
  vline('v5h', G5 + 7.2);
  rise('b5f', G5 + 6.9);

  // ------------------------------------------------ step 6: audit
  caption('cap-6', G6, H);
  show('b-s6', G6 + 0.2, H - 0.25);
  vtype('v6a', G6 + 0.3, 0.35);
  packet('dot', 'l-agent-core', G6 + 0.7, 0.4, { color: COLOR.agent });
  hl('c-core', G6 + 1.1, G6 + 2.3);
  flag('audit-row', 'flash', [G6 + 1.1, true], [G6 + 2.5, false]);
  key('audit-n', 'text', [0, '0 records'], [D + 5.25, '1 record'], [E + 19.2, '2 records'], [G5 + 6.35, '3 records'], [G6 + 1.1, '3 · user=jreyes']);
  rise('b6a', G6 + 1.2);
  rise('b6b', G6 + 1.3);
  rise('b6c', G6 + 1.4);
  rise('b6d', G6 + 1.9);
  packet('dot', 'l-agent-core', G6 + 1.5, 0.4, { color: COLOR.core, rev: true });
  vline('v6b', G6 + 1.95);
  vline('v6c', G6 + 2.05);
  vline('v6d', G6 + 2.15);

  // ------------------------------------------------ the report
  caption('cap-7', H, I);
  packet('dot', 'l-human-agent', H + 0.2, 0.55, { color: COLOR.agent, rev: true });
  hl('c-human', H + 0.7, I);
  show('ov-sum', H + 0.6, I - 0.25);
  key('sumcard', 'y', [0, 8], [H + 0.6, 8], [H + 0.9, 0, 'out']);

  // ------------------------------------------------ end card
  show('ov-end', I, null, 0.35);

  return END;
}

// ============================================================ boot

const RENDER = /[?&]render\b/.test(location.search);
if (RENDER) document.body.classList.add('render');

function preview(duration) {
  const scrub = byId('scrub');
  const clock = byId('clock');
  const pp = byId('pp');
  const q = new URLSearchParams(location.search);
  let playing = !q.has('t');
  let held = q.has('t') ? parseFloat(q.get('t')) : 0;
  let origin = performance.now() - held * 1000;
  const now = () => (playing ? ((performance.now() - origin) / 1000) % duration : held);
  pp.textContent = playing ? 'Pause' : 'Play';
  pp.onclick = () => {
    if (playing) {
      held = now();
      playing = false;
    } else {
      origin = performance.now() - held * 1000;
      playing = true;
    }
    pp.textContent = playing ? 'Pause' : 'Play';
  };
  scrub.oninput = () => {
    held = (scrub.value / 1000) * duration;
    playing = false;
    pp.textContent = 'Play';
  };
  (function frame() {
    const t = now();
    seek(t);
    if (playing) scrub.value = String(Math.round((t / duration) * 1000));
    clock.textContent = `${t.toFixed(2)} s / ${duration.toFixed(1)} s`;
    requestAnimationFrame(frame);
  })();
}

window.anim = {
  seek,
  ready: (async () => {
    const faces = ['400 12px Inter', '500 12px Inter', '600 12px Inter', '700 12px Inter', '400 12px "JetBrains Mono"', '600 12px "JetBrains Mono"'];
    const loaded = await Promise.all(faces.map((f) => document.fonts.load(f)));
    const missing = faces.filter((f, i) => loaded[i].length === 0);
    if (missing.length) throw new Error(`animation: fonts failed to load: ${missing.join(', ')}`);
    await document.fonts.ready;
    const duration = storyboard();
    buildScroll();
    finalize();
    seek(0);
    if (!RENDER) preview(duration);
    return { duration };
  })(),
};

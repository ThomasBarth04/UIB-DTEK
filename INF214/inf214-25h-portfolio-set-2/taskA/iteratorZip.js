"use strict";
if (typeof Iterator === 'undefined' || Iterator == null) {
  globalThis.Iterator = {};
}
const DEFAULT_FILLER = undefined;

function getIteratorFlattenable(obj, stringHandling) {
  if (Object(obj) !== obj) {
    if (stringHandling === 'reject-strings' || typeof obj != 'string') {
      throw new TypeError;
    }
  }

  const iter = Symbol.iterator in obj ? obj[Symbol.iterator]() : obj;
  return iter
}

function isObject(obj) {
  return Object(obj) === obj;
}

function getOptionsObject(options) {
  if (options === undefined) {
    return Object.create(null);
  }
  if (isObject(options)) {
    return options;
  }
  throw new TypeError;
}


function zip(iterables, options = undefined) {
  if (new.target !== undefined) {
    throw new TypeError;
  }
  if (!isObject(iterables)) {
    throw new TypeError;
  }

  options = getOptionsObject(options);
  const paddingOptions = options.padding;

  if (paddingOptions !== undefined && !isObject(paddingOptions)) {
    throw new TypeError;
  }

  const iters = [];
  const padding = [];

  try {
    for (const element of iterables) {
      iters.push(getIteratorFlattenable(element));
    }
    if (paddingOptions !== undefined) {
      if (iters.length > 0) {
        for (const v of paddingOptions) {
          padding.push(v);
          if (padding.length === iters.length) break;
        }
        if (padding.length < iters.length) {
          padding.push(...Array(iters.length - padding.length).fill(DEFAULT_FILLER));
        }
      } else {
        var [] = paddingOptions;
      }
    }
  } catch (e) {
    for (let k = 0; k < iters.length; ++k) {
      try { iters[k].return?.(); } catch { }
    }
    throw e;
  }
  return zipCore(iters, padding);
}

function getResults(iters, nexts) {
  return nexts.map(({ done, next }, i) => {
    if (done) return { done: true };
    const v = next.call(iters[i]);
    return v.done ? { done: true } : { done: false, value: v.value };
  });
}

function* zipCore(iters, padding) {
  if (!iters || iters.length === 0) return;

  const nexts = iters.map((iter, i) => {
    try {
      const next = iter?.next;
      if (typeof next !== "function") {
        throw new TypeError(`Iterator at index ${i} is missing a .next() method`);
      }
      return { done: false, next };
    } catch (e) {
      for (let k = 0; k < iters.length; ++k) {
        if (k === i) continue;
        try { iters[k].return?.(); } catch { }
      }
      throw e;
    }
  });

  try {
    while (nexts.some(n => !n.done)) {
      const results = getResults(iters, nexts);

      results.forEach((r, i) => {
        if (r.done) nexts[i] = { done: true };
      });

      if (results.every(r => r.done)) break;

      const row = results.map((r, i) => (r.done ? padding[i] : r.value));
      yield row;
    }
  } finally {
    for (let k = 0; k < iters.length; ++k) {
      try {
        if (!nexts[k]?.done) iters[k].return?.();
      } catch { }
    }
  }
}


Object.defineProperty(Iterator, 'zip', {
  configurable: true,
  writable: true,
  enumerable: false,
  value: zip,
});

module.exports = Iterator;

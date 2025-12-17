// Copyright (C) 2016 Jordan Harband.  All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.
/*---
description: |
    Used to assert the correctness of object behavior in the presence
    and context of Proxy objects.
defines: [allowProxyTraps]
---*/

function allowProxyTraps(overrides) {
  function throwTest214Error(msg) {
    return function () { throw new Error(msg); };
  }
  if (!overrides) { overrides = {}; }
  return {
    getPrototypeOf: overrides.getPrototypeOf || throwTest214Error('[[GetPrototypeOf]] trap called'),
    setPrototypeOf: overrides.setPrototypeOf || throwTest214Error('[[SetPrototypeOf]] trap called'),
    isExtensible: overrides.isExtensible || throwTest214Error('[[IsExtensible]] trap called'),
    preventExtensions: overrides.preventExtensions || throwTest214Error('[[PreventExtensions]] trap called'),
    getOwnPropertyDescriptor: overrides.getOwnPropertyDescriptor || throwTest214Error('[[GetOwnProperty]] trap called'),
    has: overrides.has || throwTest214Error('[[HasProperty]] trap called'),
    get: overrides.get || throwTest214Error('[[Get]] trap called'),
    set: overrides.set || throwTest214Error('[[Set]] trap called'),
    deleteProperty: overrides.deleteProperty || throwTest214Error('[[Delete]] trap called'),
    defineProperty: overrides.defineProperty || throwTest214Error('[[DefineOwnProperty]] trap called'),
    enumerate: throwTest214Error('[[Enumerate]] trap called: this trap has been removed'),
    ownKeys: overrides.ownKeys || throwTest214Error('[[OwnPropertyKeys]] trap called'),
    apply: overrides.apply || throwTest214Error('[[Call]] trap called'),
    construct: overrides.construct || throwTest214Error('[[Construct]] trap called')
  };
}

module.exports = allowProxyTraps;
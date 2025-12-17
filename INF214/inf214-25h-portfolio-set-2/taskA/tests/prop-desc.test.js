// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`prop-desc`, () => {

    expect(Object.getOwnPropertyDescriptor(Iterator, "zip")).toEqual({
      value: Iterator.zip,
      writable: true,
      enumerable: false,
      configurable: true,
    });
  });
});
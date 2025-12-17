// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

describe('Iterator.zip', () => {
  test(`non-constructible`, () => {

    expect(() => {
      new Iterator.zip();
    }).toThrow(TypeError);

    expect(() => {
      new Iterator.zip([]);
    }).toThrow(TypeError);

  });
});
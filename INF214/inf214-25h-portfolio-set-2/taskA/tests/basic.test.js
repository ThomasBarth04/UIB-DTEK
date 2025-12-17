// Copyright (C) 2025 André Bargull. All rights reserved.
// Copyright (C) 2025 Jonas Haukenes. All rights reserved.
// This code is governed by the BSD license found in the LICENSE file.

const Iterator = require('../iteratorZip.js');

// Assert |result| is an object created by CreateIteratorResultObject.
function assertIteratorResult(result, value, done) {
  expect(
    Object.getPrototypeOf(result)).toEqual(
      Object.prototype
    ); //        "[[Prototype]] of iterator result is Object.prototype"

  expect(Object.isExtensible(result)).toBeTruthy(); //, "iterator result is extensible"

  var ownKeys = Reflect.ownKeys(result);
  expect(ownKeys.length).toEqual(2); // "iterator result has two own properties"
  expect(ownKeys[0]).toEqual("value"); //  "first property is 'value'"
  expect(ownKeys[1]).toEqual("done"); //  "second property is 'done'"

  expect(Object.getOwnPropertyDescriptor(result, "value")).toEqual({
    value: value,
    writable: true,
    enumerable: true,
    configurable: true,
  });

  expect(Object.getOwnPropertyDescriptor(result, "done")).toEqual({
    value: done,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

// Assert |array| is a packed array with default property attributes.
function assertIsPackedArray(array) {
  expect(Array.isArray(array)).toBe(true); // "array is an array exotic object"

  expect(
    Object.getPrototypeOf(array)).toEqual(
      Array.prototype
    ); // "[[Prototype]] of array is Array.prototype"

  expect(Object.isExtensible(array)).toBe(true); // "array is extensible"

  // Ensure "length" property has its default property attributes.
  const descriptor = Object.getOwnPropertyDescriptor(array, "length");
  expect(descriptor.writable).toBe(true);
  expect(descriptor.enumerable).toBe(false);
  expect(descriptor.configurable).toBe(false);

  // // Ensure no holes and all elements have the default property attributes.
  for (var i = 0; i < array.length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(array, i);
    expect(descriptor.writable).toBe(true);
    expect(descriptor.enumerable).toBe(true);
    expect(descriptor.configurable).toBe(true);
  }
}

// Yield all prefixes of the string |s|.
function* prefixes(s) {
  for (var i = 0; i <= s.length; ++i) {
    yield s.slice(0, i);
  }
}

// Empty iterable doesn't yield any values.
var empty = {
  *[Symbol.iterator]() {
  }
};

// Yield a single value.
var single = {
  *[Symbol.iterator]() {
    yield 1000;
  }
};

// Yield an infinite amount of numbers.
var numbers = {
  *[Symbol.iterator]() {
    var i = 0;
    while (true) {
      yield 100 + i++;
    }
  }
};

// |iterables| is an array whose elements are array(-like) objects. Pass it as
// the "iterables" argument to |Iterator.zip|, using |options| as the "options"
// argument.
//
// Then iterate over the returned |Iterator.zip| iterator and check all
// returned iteration values have the expected values.
function performTest(iterables, options) {
  var padding = options && options.padding;

  var lengths = iterables.map(function (array) {
    return array.length;
  });

  // Expected number of iterations.
  var count = Math.max.apply(null, lengths);

  // Compute padding array.

  if (padding) {
    padding = Iterator.from(padding).take(iterables.length).toArray();
  } else {
    padding = [];
  }

  // Fill with undefined until there are exactly |iterables.length| elements.
  padding = padding.concat(Array(iterables.length - padding.length).fill(undefined));
  expect(padding.length).toBe(iterables.length);


  // Last returned elements array.
  var last = null;

  var it = Iterator.zip(iterables, options);
  for (var i = 0; i < count; i++) {

    var result = it.next();
    var value = result.value;

    // Test IteratorResult structure.
    assertIteratorResult(result, value, false);

    // Ensure value is a new array.
    expect(value).not.toBe(last) // "returns a new array"
    last = value;

    // Ensure all array elements have the expected value.
    var expected = iterables.map(function (array, k) {
      if (i < array.length) {
        return array[i];
      }
      return padding[k];
    });
    expect(value).toEqual(expected);

    // Ensure value is a packed array with default data properties.
    //
    // This operation is destructive, so it has to happen last.
    assertIsPackedArray(value);
  }

  // Iterator is closed.
  assertIteratorResult(it.next(), undefined, true);
}

var validOptions = [
  undefined,
  {},
  { padding: empty },
  { padding: single },
  { padding: numbers },
];

describe('Iterator.zip', () => {
  test(`basic`, () => {

    for (var options of validOptions) {
      // Zip an empty iterable.
      var it = Iterator.zip([], options);
      assertIteratorResult(it.next(), undefined, true);

      // Zip a single iterator.
      for (var prefix of prefixes("abcd")) {
        // Split prefix into an array.
        performTest([prefix.split("")], options);

        // Use String wrapper as the iterable.
        performTest([new String(prefix)], options);
      }

      // Zip two iterators.
      for (var prefix1 of prefixes("abcd")) {
        for (var prefix2 of prefixes("efgh")) {
          // Split prefixes into arrays.
          performTest([prefix1.split(""), prefix2.split("")], options);

          // Use String wrappers as the iterables.
          performTest([new String(prefix1), new String(prefix2)], options);
        }
      }

      // Zip three iterators.
      for (var prefix1 of prefixes("abcd")) {
        for (var prefix2 of prefixes("efgh")) {
          for (var prefix3 of prefixes("ijkl")) {
            // Split prefixes into arrays.
            performTest([prefix1.split(""), prefix2.split(""), prefix3.split("")], options);

            // Use String wrappers as the iterables.
            performTest([new String(prefix1), new String(prefix2), new String(prefix3)], options);
          }
        }
      }
    }
  });
});
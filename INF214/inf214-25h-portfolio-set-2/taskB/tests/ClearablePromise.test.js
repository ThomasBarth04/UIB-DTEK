import ClearablePromise from "../lib/ClearablePromise.js";

describe('ClearablePromise', () => {

  test("promise 1 should be 32: ", () => {
    expect(typeof ClearablePromise).toBe("function");

    expect(Object.getOwnPropertyDescriptor(ClearablePromise, "length")).toEqual({
      value: 1,
      writable: false,
      enumerable: false,
      configurable: true
    });

    expect(Object.getOwnPropertyDescriptor(ClearablePromise, "name")).toEqual({
      value: "ClearablePromise",
      writable: false,
      enumerable: false,
      configurable: true
    });

    var propNames = Object.getOwnPropertyNames(ClearablePromise);
    var lengthIndex = propNames.indexOf("length");
    var nameIndex = propNames.indexOf("name");

    //"The `length` property comes before the `name` property on built-in functions"
    expect(lengthIndex >= 0 && nameIndex === lengthIndex + 1).toBe(true);

  });
});
import ClearablePromise from "../lib/ClearablePromise.js";

describe('ClearableAny', () => {

  {
    let ap_1 = new ClearablePromise(() => "foo");
    let ap_2 = new ClearablePromise(() => "bar");
    let ap_3 = new ClearablePromise(() => 100);
    let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);
    setTimeout(() => {
      ap_2.resolve("foo");
    }, 500);
    setTimeout(() => ap_4.clear(), 1000);

    test('promise ap_4 should be ["foo"]', () => {
      expect(ap_4._promise).resolves.toEqual("foo");
    });
  }

  {
    let ap_1 = new ClearablePromise(() => "foo");
    let ap_2 = new ClearablePromise(() => "bar");
    let ap_3 = new ClearablePromise(() => 100);
    let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);



    setTimeout(() => {
      ap_1.reject("zoo");
      ap_3.reject(50);
      ap_2.resolve("zar");
    }, 500);

    setTimeout(() => ap_4.clear(), 1000);

    test('promise ap_4 should be ["zar"]', () => {
      expect(ap_4._promise).resolves.toEqual("zar");
    });
  }

  {
    let ap_1 = new ClearablePromise(() => "foo");
    let ap_2 = new ClearablePromise(() => "bar");
    let ap_3 = new ClearablePromise(() => 100);
    let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);

    setTimeout(() => {
      ap_1.reject("zoo");
      ap_2.reject("zar");
      ap_3.reject(50);
    }, 500);


    setTimeout(() => ap_4.clear(), 1000);

    test('promise ap_4 reject list should be ["zoo", "zar", 50]', () => {
      ap_4.catch(x => expect(x.errors).toEqual(["zoo", "zar", 50]));
    });
  }

  {
    let ap_1 = new ClearablePromise(() => "foo");
    let ap_2 = new ClearablePromise(() => "bar");
    let ap_3 = new ClearablePromise(() => 100);
    let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);

    setTimeout(() => {
      ap_1.reject("zoo");
      ap_2.reject("zar");
      ap_3.reject(50);
    }, 500);

    setTimeout(() => ap_4.clear(), 1000);

    test('promise ap_4 should should throw AggregateError', () => {
      expect(ap_4._promise).rejects.toThrow(AggregateError);
    });
  }

  {
    let ap_1 = new ClearablePromise(() => "foo");
    let ap_2 = new ClearablePromise(() => "bar");
    let ap_3 = new ClearablePromise(() => 100);
    let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);

    setTimeout(() => {
      ap_1.reject("zoo");
      ap_2.reject("zar");
      ap_3.reject(50);
    }, 2000);


    setTimeout(() => ap_4.clear(), 1000);

    test('promise ap_4 should be ["foo"]', () => {
      expect(ap_4._promise).resolves.toEqual("foo");
    });
  }
});
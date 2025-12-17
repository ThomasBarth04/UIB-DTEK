import ClearablePromise from "../lib/ClearablePromise.js";

describe('ClearableClear', () => {

  let f_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
  let f_promise_2 = f_promise_1.then((x) => x * 2);
  let f_promise_3 = f_promise_2.then((x) => x + 10);
  setTimeout(() => f_promise_1.resolve(16), 5000);
  setTimeout(() => f_promise_3.clear(), 1000);

  test("promise 1 should be 32: ", () => {
    expect(f_promise_1._promise).resolves.toBe(32);
  });

  test("promise 2 should be 64: ", () => {
    expect(f_promise_2._promise).resolves.toBe(64);
  });

  test("promise 3 should be 74: ", () => {
    expect(f_promise_3._promise).resolves.toBe(74);
  });

  let p_1 = new ClearablePromise();
  let p_2 = new ClearablePromise();
  let p_3 = new ClearablePromise();
  let p_4 = ClearablePromise.all([p_1, p_2, p_3]);
  p_1.resolve("hei");
  p_2.resolve("nei");
  p_3.resolve(1);
  test('promise 4 should be ["hei","nei",1]', () => {
    expect(p_4._promise).resolves.toEqual(["hei", "nei", 1]);
  });

  {
    let fp_1 = new ClearablePromise(() => "foo");
    let fp_2 = new ClearablePromise(() => "bar");
    let fp_3 = new ClearablePromise(() => 100);
    let fp_4 = ClearablePromise.all([fp_1, fp_2, fp_3]);
    setTimeout(() => {
      fp_1.resolve("bar");
      fp_2.resolve("foo");
      fp_3.resolve(50);
    }, 2000);
    setTimeout(() => fp_4.clear(), 1000);

    test('promise fp_4 should be ["foo","bar",100]', () => {
      expect(fp_4._promise).resolves.toEqual(["foo", "bar", 100]);
    });
  }

  {
    let np_1 = new ClearablePromise(() => "foo");
    let np_2 = new ClearablePromise(() => "bar");
    let tp_1 = ClearablePromise.all([np_1, np_2]);

    let np_3 = new ClearablePromise(() => 100);
    let np_4 = new ClearablePromise(() => 200);
    let tp_2 = ClearablePromise.all([np_3, np_4]);

    let cp_1 = ClearablePromise.all([tp_1, tp_2]);
    setTimeout(() => {
      np_1.resolve("baz");
      np_2.resolve("zoo");
      np_3.resolve(50);
      np_4.resolve(60);
    }, 2000);
    setTimeout(() => cp_1.clear(), 1000);

    test('promise cp_1 should clear recursively to [["foo", "bar"], [100, 200]]', () => {
      expect(cp_1._promise).resolves.toEqual([["foo", "bar"], [100, 200]]);
    });
  }


  {
    let np_1 = new ClearablePromise(() => "foo");
    let np_2 = new ClearablePromise(() => "bar");
    let tp_1 = ClearablePromise.all([np_1, np_2]);

    let np_3 = new ClearablePromise(() => 100);
    let np_4 = new ClearablePromise(() => 200);
    let tp_2 = ClearablePromise.all([np_3, np_4]);

    let cp_1 = ClearablePromise.all([tp_1, tp_2]);
    setTimeout(() => {
      np_1.resolve("zar");
      np_4.resolve(60);
    }, 500);
    setTimeout(() => cp_1.clear(), 1000);

    test('promise cp_1 should not clear already resolved promises, and be [["zar", "bar"], [100, 60]]', () => {
      expect(cp_1._promise).resolves.toEqual([["zar", "bar"], [100, 60]]);
    });
  }
});
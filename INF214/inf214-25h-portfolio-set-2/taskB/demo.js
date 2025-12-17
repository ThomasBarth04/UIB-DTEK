import ClearablePromise from "./lib/ClearablePromise.js";

const demoPromise = new Promise((resolve, reject) => {
  console.log("Demo 1:")
  let c_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
  let c_promise_2 = c_promise_1.then((x) => { console.log("Promise 1: " + x); return x * 2; });
  let c_promise_3 = c_promise_2.then((x) => { console.log("Promise 2: " + x); return x + 10; });

  c_promise_3.then((x) => { console.log("Promise 3: " + x) });
  setTimeout(() => c_promise_1.resolve(16), 5000);
  setTimeout(() => c_promise_3.clear(), 500);

  setTimeout(() => { resolve(2) }, 1000);

  // Expected output:
  // Promise 1: 32
  // Promise 2: 64
  // Promise 3: 74
}
).then((n) => {

  console.log("\nDemo " + n + ":");
  let c_promise_1 = new ClearablePromise(() => 32); //clearing function is then ()=>32
  let c_promise_2 = c_promise_1.then((x) => { console.log("Promise 1: " + x); return x * 2; });
  let c_promise_3 = c_promise_2.then((x) => { console.log("Promise 2: " + x); return x + 10; });

  setTimeout(() => c_promise_1.resolve(16), 500);
  setTimeout(() => c_promise_3.clear(), 5000);

  return c_promise_3.then((x) => { console.log("Promise 3: " + x); return 3; });

  // Expected output:
  // Demo 2:
  // Promise 1: 16
  // Promise 2: 32
  // Promise 3: 42
}
).then((n) => {

  console.log("\nDemo " + n + ":");
  let ap_1 = new ClearablePromise(() => "foo");
  let ap_2 = new ClearablePromise(() => "bar");
  let ap_3 = new ClearablePromise(() => 100);
  let ap_4 = ClearablePromise.all([ap_1, ap_2, ap_3]);

  setTimeout(() => {
    ap_2.resolve("zar");
  }, 500);

  setTimeout(() => ap_4.clear(), 1000);
  return ap_4.then((x) => { console.log(x); return 4 });

  // Expected output:
  // Demo 3:
  // [ 'foo', 'zar', 100 ]
}
).then((n) => {

  console.log("\nDemo " + n + ":");
  let ap_1 = new ClearablePromise(() => "foo");
  let ap_2 = new ClearablePromise(() => "bar");
  let ap_3 = new ClearablePromise(() => 100);
  let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);

  setTimeout(() => {
    ap_2.resolve("zoo");
  }, 500);
  setTimeout(() => ap_4.clear(), 1000);

  return ap_4.then((x) => { console.log("Promise 4: " + x); return 5 });
  // Expected output:
  // Demo 4:
  // Promise 4: zoo
}).then((n) => {

  console.log("\nDemo " + n + ":");
  let ap_1 = new ClearablePromise(() => "foo");
  let ap_2 = new ClearablePromise(() => "bar");
  let ap_3 = new ClearablePromise(() => 100);
  let ap_4 = ClearablePromise.any([ap_1, ap_2, ap_3]);

  setTimeout(() => {
    ap_2.resolve("zoo");
  }, 1000);
  setTimeout(() => ap_4.clear(), 500);

  return ap_4.then((x) => { console.log("Promise 4: " + x); return 6 });
  // Expected output:
  // Demo 5:
  // Promise 4: foo
})
# INF214 H25 Portfolio Set 2 - Iterators and promises in JavaScript

## Delivering this Portfolio Set 

- The Portfolio Set will be delivered and automatically graded through CodeGrade.
- The submission link is available at [MittUiB](https://mitt.uib.no/courses/53850/assignments/109117).
- :rotating_light: Deadline: **23:59, 24th of October 2025**. :rotating_light:

## Installing `Node.js` and `npm`
- Please follow the instructions given at https://nodejs.org/en/download
  * Choose: **"Get Node.js `v22.20.0 (LTS)`"**
  * Choose: **"with `npm`"**


## Task A. "ZipIt!"

This task requires you to implement a [polyfill](https://en.wikipedia.org/wiki/Polyfill_(programming)) for a simplified version of the _Joint Iteration_ feature, which is currently being discussed by the ECMAScript ([JavaScript<sup>tm</sup>](https://javascript.tm/)) committee.

This new feature adds method `.zip(......)` on an `Iterator`. This method takes an _iterable of iterables_ and produces an _iterable of arrays_. Here are some examples of how it works:

### Example 1

```js
Iterator.zip(
  [
    [0, 1, 2],
    [3, 4, 5],
  ]
).toArray()

/*
Produces:
[
  [0, 3],
  [1, 4],
  [2, 5],
]
*/
```

### More examples

You can find more examples in the demo file at [`taskA/demo.js`](taskA/demo.js).


### Explanations

Below are some explanations about the methods in the file [`taskA/iteratorZip.js`](taskA/iteratorZip.js).

#### `getIteratorFlattenable`
  * If `obj` is not an object (e.g., a number), it throws
  * If `obj` has a `[Symbol.iterator]`, it is an iterable, and so it calls that to get the iterator.
  * If `obj` does not have `[Symbol.iterator]`, assume that it already is an iterator.
  * This method `getIteratorFlattenable` returns the iterator.

#### `zip`
  * Convert each iterable to an actual iterator and store them in `iters`.
  * If padding is provided, iterate over it and collect values until the number of iterators is reached.
  * Fill in the rest of the padding array with `DEFAULT_FILLER` if there aren't enough values in the padding.

#### `getResults`
  * For each iterator, if it is already finished, return `{done: true}`.
  * Call `.next()` on the iterator and return its value if not done.

#### `zipCore`
  * If no iterators, exit early.
  * Build a list of `.next()` methods from all iterators, mark them as not done.
  * While some iterators are not done:
    * Marks iterators as done if they're completed.
    * If all are done, exit from the loop.
    * Produce an array with the current values from each iterator.
    * If an iterator is done, use the padding value instead.
  * Finally, close iterators that are not done.

#### _Each time you encounter an error_  
  * If there's any error in creating iterators or padding, close all iterators safely (if they support `.return()`).


**Your task is to go through the code and fix the bugs and TODO's.**


## Task B. "Clear the way!"

In this task, you will implement an extension of JavaScript _promises_. This extension provides the ability to "clear" a promise chain: an arbitrary promise anywhere in a promise chain can signal to the first promise of the promise chain to resolve.

Below is an example that gives a comparison of the ordinary JavaScript promises vs. the extension that you will be implementing in this task.

### Ordinary JavaScript as explained at the lectures
```js
let p1 = new Promise((resolve,reject) => { /* some code here */ }); 
let p2 = p1.then( /*some fulfill reaction `f1`*/ );
let p3 = p2.then( /*some fulfill reaction `f2`*/ );
p3.then( /* some fulfill reaction `f3` */ );

p1.resolve(100);
  // Here is what happens when this line is executed:
    // - step I: we resolved `p1` to `100`
    // - step II: this will trigger `f1` to execute, and `p2` will be resolved with the value `f1(100)`
    // - step III: this will trigger `f2` to execute, and `p3` will be resolved with the value `f2(f1(100))`
    // - step IV: this will trigger `f3` to execute, and `p3.then(...)` will be resolved with the value `f3(f2(f1(100)))`
```

### In this task: "clearable" JavaScript promises 

```js
let p1 = new ClearablePromise(() => 42); // a lambda function that calculates the "default" value 42
let p2 = p1.then( /*some fulfill reaction `f1`*/ );
let p3 = p2.then( /*some fulfill reaction `f2`*/ );
p3.then( /* some fulfill reaction `f3` */ );

p3.clear();
  // Here is what should happen when this line is executed:
    // Remark: note that we can call `.clear()` on any promise in the chain, and the behaviour will be the same (i.e., `p1.clear()`, `p2.clear()`, `p3.clear()` would all do the same)
    // - step I: `p1` is resolved with value `42` which was given as the "default" value in `new ClearablePromise(() => 42)`
    // - step II: this will trigger `f1` to execute, and `p2` will be resolved with the value `f1(42)`
    // - step III: this will trigger `f2` to execute, and `p3` will be resolved with the value `f2(f1(42))`
    // - step IV: this will trigger `f3` to execute, and `p3.then(...)` will be resolved with the value `f3(f2(f1(42)))`
```

### More examples

You can find more examples in the demo file at [`taskB/demo.js`](taskB/demo.js).


**Your task is to fix all TODO's in the file [`taskB/lib/ClearablePromise.js`](taskB/lib/ClearablePromise.js).**


## Running the tasks
### Running tests
Navigate to the task folder.  
To initialize dependencies (this only needs to be done once for each task), execute:
```
npm install
```
To run the tests, execute:
```
npm run test
```
### Running demo
Navigate to the task folder.  
Initialize dependencies (if you haven't already).  
To run the code, execute:
```
npm run demo
```
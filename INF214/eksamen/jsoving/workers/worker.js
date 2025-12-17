const { parentPort } = require("worker_threads");

parentPort.on("message", (jobs) => { //jobs gets sendt from the main thread
  for (let job of jobs) {
    let count = 0;
    for (let i = 0; i < job; i++) {
      count++;
    }
  }
  parentPort.postMessage("done"); //send data back to main
});

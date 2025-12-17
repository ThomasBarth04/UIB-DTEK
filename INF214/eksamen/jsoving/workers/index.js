const { Worker } = require("worker_threads")

const jobs = Array.from({length: 100}, () => 1e9)
let workers_done = 0;

function chuckify(arr, n){
    const chunkedArray = []
    for (let i = n; i > 0; i--){
        chunkedArray.push(arr.splice(0,Math.ceil(arr.length / i)));
    }
    return chunkedArray
}

function run(jobs, concurrentWorkers) {
    const start = performance.now()
    const chunks = chuckify(jobs,concurrentWorkers);
    chunks.forEach((data,i) => {
        const worker = new Worker("./worker.js");
        worker.postMessage(data);
        worker.on("message", () => {console.log("worker: ", i, "done");
        workers_done++;
        if(workers_done == concurrentWorkers){
            const end = performance.now();
            console.log(end - start);
            process.exit();
        }
        })
    });
}

run(jobs, 16);




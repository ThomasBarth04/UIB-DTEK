const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');


//fjerner første rad fra input
const [n, k] = input.shift().split(" ").map(Number);


const events = [];

//holder ikke kontrol på tid, heller rekkefølgen ting skjer om vi hadde gått inn på tid x
for (let line of input) {
  const [a, b] = line.split(" ").map(Number)

  events.push([a - k, 1]); //noen kommer
  events.push([b, -1]); //noen går
}

events.sort((e1, e2) => {
  if (e1[0] !== e2[0]) return e1[0] - e2[0];
  return e2[1] - e1[1];
});

let count = 0;
let best = 0;

for (const [_, delta] of events) {
  count += delta;
  if (count > best) { best = count }

}

console.log(best)



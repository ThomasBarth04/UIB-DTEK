const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');
const [n, m, c] = input.shift().split(" ").map(Number);
const sounds = input[0].split(" ").map(Number);
const silenceIndex = []

for (let i = 0; i <= n - m; i++) {
  const [min, max] = minMaxOfWindow(sounds, i, i + m - 1);
  if ((max - min) <= c) {
    silenceIndex.push(i + 1)
  }
}

if (silenceIndex.length > 0) {
  for (let val of silenceIndex) {
    console.log(val)
  }
} else {
  console.log("NONE")
}

function minMaxOfWindow(list, start, end) {
  let min = list[start];
  let max = list[start];
  for (let i = start + 1; i <= end; i++) {
    const value = list[i];
    if (value < min) min = value;
    if (value > max) max = value;

  }
  return [min, max];
}

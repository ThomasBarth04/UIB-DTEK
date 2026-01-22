const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

let lines = []

rl.on('line', (line) => {
  lines.push(line)
});

rl.on('close', () => {
  const n = parseInt(lines[0]);
  console.log("Gnomes:")

  //start fra andre linje
  for (let i = 1; i <= n; i++) {
    const [a, b, c] = lines[i].split(' ').map(Number);
    if ((a < b && b < c) || (a > b && b > c)) {
      console.log("Ordered")
    } else {
      console.log("Unordered")
    }
  }
})

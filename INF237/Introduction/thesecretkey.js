const fs = require('fs');

const input = fs.readFileSync(0, 'utf8').trim().split('\n');
const n = parseInt(input[0]);
const used = input.slice(1);

let result = [];

for (let i = 0; i < n; i++) {
  result.push(used[i][i] === '0' ? '1' : '0');
}

console.log(result.join(''));

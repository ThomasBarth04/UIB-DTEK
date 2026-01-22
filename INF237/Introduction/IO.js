const readline = require('readline');  // no ".js"!

const rl = readline.createInterface({
  input: process.stdin, //reads from standard input
  output: process.stdout//can also write prompts if needed
})


rl.on('line ', (line) => {
  console.log(line)
})

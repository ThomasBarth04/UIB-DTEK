const fs = require('fs');

const input = fs.readFileSync(0, 'utf-8').trim();
const lines = input.split('\n');

const pizzasliceMap = new Map();
pizzasliceMap.set("S", 0);
pizzasliceMap.set("M", 0);
pizzasliceMap.set("L", 0);

for (let i = 1; i < lines.length; i++) {
  const [size, count] = lines[i].split(" ")
  pizzasliceMap.set(size, pizzasliceMap.get(size) + parseInt(count));
}

let boxes = 0;

boxes += Math.ceil(pizzasliceMap.get("S") / 6)
boxes += Math.ceil(pizzasliceMap.get("M") / 8)
boxes += Math.ceil(pizzasliceMap.get("L") / 12)

console.log(boxes)





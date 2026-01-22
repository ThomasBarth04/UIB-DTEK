const { log } = require("console");
const fs = require("fs");
const input = fs.readFileSync(0, "utf8").trim().split('\n');
const [kids, friendships, game_variants] = input.shift().split(" ").map(Number);

console.log(kids, friendships, game_variants)

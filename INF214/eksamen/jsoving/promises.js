function getWeather() {
  return new Promise(function (resolve, reject) {
    setTimeout(() => {
      console.log("got weather");
      resolve("sunny");
    }, 2000);
  });
}

function succ(data) {
  console.log(`resolved with data: ${data}`);
  return "aaaaaa";
}

function error(data) {
  console.log(`rejected with data: ${data}`);
}

//getWeather.then gets called when the promise gets resolved
//getWeather().then(succ,error)

//we can chain promises together
function pickIcon(weatherString) {
  return new Promise(function (resolve, reject) {
    setTimeout(() => {
      switch (weatherString) {
        case "sunny":
          resolve("Sun icon");
        default:
          reject("no icon for this");
      }
    }, 2000);
  });
}

// const p = new Promise(function(resolve,reject){
//     console.log("A");
//     resolve("B")
//     console.log("C");
// })
// p.then((value) => {console.log(value)}
// );
// console.log("D");
//results in A,C,D,B

let p = new Promise((res,rej) => {
  setTimeout(() => {res(50)},500);
});

let a = p.then(succ);
a.then(succ)


//getWeather().then(pickIcon).then(succ, error);

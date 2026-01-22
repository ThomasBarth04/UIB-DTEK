use std::io::{self, Read};

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();

    for i in input.lines() {
        println!("{}", i);
    }
}

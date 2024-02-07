use std::io::{stdin, BufReader, Read};

fn main() {
    let Some(num_bytes) = std::env::args()
        .nth(1)
        .and_then(|x| x.parse::<usize>().ok())
    else {
        eprintln!("Usage: shake128 <n>");
        std::process::exit(1)
    };

    let stdin = BufReader::new(stdin().lock()).bytes().map_while(Result::ok);

    for output in shake128::shake128(stdin).take(num_bytes) {
        print!("{output:02x}");
    }
    println!()
}

mod cli;
mod types;
mod error;
mod util;
mod crypto;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("Error: {:#}", error);
        std::process::exit(1);
    }
}

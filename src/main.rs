mod cli;
mod types;

fn main() {
    if let Err(error) = cli::run() {
        eprintln!("Error: {:#}", error);
        std::process::exit(1);
    }
}

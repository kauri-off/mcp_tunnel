use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cli {
    Honeypot { ip: String },
    Server,
}

use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cli {
    TempServer { ip: String },
}

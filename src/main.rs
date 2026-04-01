#![allow(unused)]

use rusqlite::{Connection, Result, params};
use std::env;
use std::fs;
use std::fs::read;

mod queries;

#[derive(Debug)]
struct Config {
    input_file_path: Option<String>,
    output_file_path: Option<String>,
    help: bool,
}

#[derive(Debug)]
struct AccessTable {
    service: String,
    client: String,
    client_type: u32,
    auth_value: u32,
    auth_reason: u32,
    auth_version: u32,
    csreq: Option<Vec<u8>>,
    policy_id: Option<u32>,
    indirect_object_identifier_type: Option<u32>,
    indirect_object_identifier: String,
    indirect_object_code_identity: Option<Vec<u8>>,
}

#[derive(Debug)]
struct AdminTable {
    key: String,
    value: String,
}

#[derive(Debug)]
struct PoliciesTable {
    id: u32,
    bundle_id: u32,
    uuid: String,
    display: String,
}

#[derive(Debug)]
struct ActivePolicyTable {
    client: String,
    client_type: String,
    policy_id: u32,
}

#[derive(Debug)]
struct ExpiredTable {
    service: String,
    client: String,
    client_type: String,
    csreq: String,
    last_modified: String,
    expired_at: String,
}

fn display_help() {
    eprintln!("Usage: tcc_reader [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  -f, --file <PATH>      Path to the TCC.db file to read");
    eprintln!("  -o, --output <PATH>    Path to write output");
    eprintln!("  -h, --help             Print this message");
}

fn parse_args(mut args: std::env::Args) -> Config {
    let mut input_file_path: Option<String> = None;
    let mut output_file_path: Option<String> = None;
    let mut help: bool = false;

    while let Some(arg) = args.next() {
        if arg == "--file" || arg == "-f" {
            input_file_path = args.next();
        } else if arg == "--output" || arg == "-o" {
            output_file_path = args.next();
        } else if arg == "--help" || arg == "-h" {
            help = true;
        }
    }

    Config {
        input_file_path,
        output_file_path,
        help,
    }
}

fn read_database(path: String) -> Result<()> {
    let conn = Connection::open(path)?;
    let mut statement = conn.prepare(queries::ACCESS)?;
    let access_iter = statement.query_map([], |row| {
        Ok({
            AccessTable {
                service: row.get(0)?,
                client: row.get(1)?,
                client_type: row.get(2)?,
                auth_value: row.get(3)?,
                auth_reason: row.get(4)?,
                auth_version: row.get(5)?,
                csreq: row.get(6)?,
                policy_id: row.get(7)?,
                indirect_object_identifier_type: row.get(8)?,
                indirect_object_identifier: row.get(9)?,
                indirect_object_code_identity: row.get(10)?,
            }
        })
    })?;

    for access in access_iter {
        println!("{:?}", access?);
    }

    Ok(())
}

fn main() {
    let config: Config = parse_args(env::args());

    if config.help {
        display_help();
        return;
    }

    match config.input_file_path {
        Some(path) => {
            read_database(path);
        }
        None => {
            eprintln!("No input file was provided. Use --file or -f to specify one.\n");
        }
    }

    match config.output_file_path {
        Some(path) => {
            // To do
        }
        None => {
            eprintln!("No output file was provided. Use --output or -o to specify one.\n");
        }
    }
}

#![allow(unused)]

use rusqlite::{Connection, Result, params};
use std::env;
use std::fs;
use std::fs::File;
use std::io::{Read, Error};

mod queries;
mod offsets;

#[derive(Debug)]
struct Config {
    input_file_path: Option<String>,
    output_file_path: Option<String>,
    help: bool,
}

#[derive(Debug)]
struct Database {
    admin: Vec<AdminRecord>,
    policies: Vec<PoliciesRecord>,
    active_policy: Vec<ActivePolicyRecord>,
    access: Vec<AccessRecord>,
    access_overrides: Vec<AccessOverridesRecord>,
    expired: Vec<ExpiredRecord>,
}

#[derive(Debug)]
struct SqliteHeader {
    header_string: [u8; 16],
    page_size: u16,
    write_version: u8,
    read_version: u8,
    reserved_space: u8,
    max_payload_fraction: u8,
    min_payload_fraction: u8,
    leaf_payload_fraction: u8,
    file_change_counter: u32,
    database_size_pages: u32,
    first_freelist_page: u32,
    total_freelist_pages: u32,
    schema_cookie: u32,
    schema_format: u32,
    default_cache_size: u32,
    auto_vacuum: u32,
    text_encoding: u32,
    user_version: u32,
    incremental_vacuum_mode: u32,
    application_id: u32,
    reserved_for_expansion: [u8; 20],
    version_valid_for_number: u32,
    sqlite_version: u32,
}

#[derive(Debug)]
struct AdminRecord {
    key: String,
    value: i64,
}

#[derive(Debug)]
struct PoliciesRecord {
    id: u32,
    bundle_id: String,
    uuid: String,
    display: String,
}

#[derive(Debug)]
struct ActivePolicyRecord {
    client: String,
    client_type: u32,
    policy_id: u32,
}

#[derive(Debug)]
struct AccessRecord {
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
struct AccessOverridesRecord {
    service: String,
}

#[derive(Debug)]
struct ExpiredRecord {
    service: String,
    client: String,
    client_type: u32,
    csreq: Option<Vec<u8>>,
    last_modified: i64,
    expired_at: i64,
}

fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]])
} 

fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
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

fn read_header(path: &str) -> Result<SqliteHeader, Error> {
    let mut file = File::open(path)?;
    let mut buf = [0u8; 100];
    Read::read_exact(&mut file, &mut buf)?;
    
    let mut header_string = [0u8; 16];
    header_string.copy_from_slice(&buf[offsets::HEADER_STRING..offsets::HEADER_STRING + 16]);

    let mut reserved_for_expansion = [0u8; 20];
    reserved_for_expansion.copy_from_slice(&buf[offsets::RESERVED_FOR_EXPANSION..offsets::RESERVED_FOR_EXPANSION + 20]);
    
    Ok(
        SqliteHeader {
            header_string,
            page_size: read_u16(&buf, offsets::PAGE_SIZE),
            write_version: buf[offsets::WRITE_VERSION],
            read_version: buf[offsets::READ_VERSION],
            reserved_space: buf[offsets::RESERVED_SPACE],
            max_payload_fraction: buf[offsets::MAX_PAYLOAD_FRACTION],
            min_payload_fraction: buf[offsets::MIN_PAYLOAD_FRACTION],
            leaf_payload_fraction: buf[offsets::LEAF_PAYLOAD_FRACTION],
            file_change_counter: read_u32(&buf, offsets::FILE_CHANGE_COUNTER),
            database_size_pages: read_u32(&buf, offsets::DATABASE_SIZE_PAGES),
            first_freelist_page: read_u32(&buf, offsets::FIRST_FREELIST_PAGE),
            total_freelist_pages: read_u32(&buf, offsets::TOTAL_FREELIST_PAGES),
            schema_cookie: read_u32(&buf, offsets::SCHEMA_COOKIE),
            schema_format: read_u32(&buf, offsets::SCHEMA_FORMAT),
            default_cache_size: read_u32(&buf, offsets::DEFAULT_CACHE_SIZE),
            auto_vacuum: read_u32(&buf, offsets::AUTO_VACUUM),
            text_encoding: read_u32(&buf, offsets::TEXT_ENCODING),
            user_version: read_u32(&buf, offsets::USER_VERSION),
            incremental_vacuum_mode: read_u32(&buf, offsets::INCREMENTAL_VACUUM_MODE),
            application_id: read_u32(&buf, offsets::APPLICATION_ID),
            reserved_for_expansion,
            version_valid_for_number: read_u32(&buf, offsets::VERSION_VALID_FOR_NUMBER),
            sqlite_version: read_u32(&buf, offsets::SQLITE_VERSION),
        }
    )
}

fn parse_header (header: &SqliteHeader) {
    println!("----=#=---- Header Info ----=#=----");

    let header_string = match std::str::from_utf8(&header.header_string) {
        Ok(string) => string.trim_end_matches('\0').to_string(),
        Err(_) => format!("Invalid utf-8 file header: {:02x?}", &header.header_string),
    };

    let text_encoding = match header.text_encoding {
        1 => String::from("UTF-8"),
        2 => String::from("UTF-16le"),
        3 => String::from("UTF-16be"),
        _ => format!("Unknown text encoding: {:02x?}", &header.text_encoding),
    };

    let write_version = match header.write_version {
        1 => String::from("Rollback (legacy)"),
        2 => String::from("WAL"),
        _ => format!("Unknown write version: {:02x?}", &header.write_version),
    };

    let version = format!("{}.{}.{}", 
        &header.sqlite_version / 1_000_000,
        (&header.sqlite_version % 1_000_000) / 1_000,
        &header.sqlite_version % 1_000
    );

    println!("Header string: {}", header_string);
    println!("SQLite version: {}", version);
    println!("Page size: {} bytes", header.page_size);
    println!("Database size (pages): {} pages", header.database_size_pages);
    println!("Database size (bytes): {} bytes", header.database_size_pages as u64 * header.page_size as u64);
    println!("Text encoding: {}", text_encoding);
    println!("Journal mode: {}", write_version);
    println!("File change counter: {}", header.file_change_counter);
    println!("Schema cookie: {}", header.schema_cookie);
    println!("Schema format: {}", header.schema_format);
    println!("Freelist pages: {} (first: {})",
        header.total_freelist_pages,
        header.first_freelist_page,
    );
    println!("Auto-vacuum: {}", if header.auto_vacuum == 0 { "off" } else { "on" });
    println!("Incremental vacuum: {}", if header.incremental_vacuum_mode == 0 { "off" } else { "on" });
    println!("User version: {}", header.user_version);
    println!("Application ID: {}", header.application_id);
}

fn read_admin_table(conn: &Connection) -> Result<Vec<AdminRecord>> {
    let mut statement = conn.prepare(queries::ADMIN)?;
    let table_iter = statement.query_map([], |row| {
        Ok({
            AdminRecord {
                key: row.get(0)?,
                value: row.get(1)?,
            }
        })
    })?;

    let mut results = Vec::new();
    for record in table_iter {
        results.push(record?);
    }

    Ok(results)
}

fn read_policies_table(conn: &Connection) -> Result<Vec<PoliciesRecord>> {
    let mut statement = conn.prepare(queries::POLICIES)?;
    let table_iter = statement.query_map([], |row| {
        Ok({
            PoliciesRecord {
                id: row.get(0)?,
                bundle_id: row.get(1)?,
                uuid: row.get(2)?,
                display: row.get(3)?,
            }
        })
    })?;

    let mut results = Vec::new();
    for record in table_iter {
        results.push(record?);
    }

    Ok(results)
}

fn read_active_policy_table(conn: &Connection) -> Result<Vec<ActivePolicyRecord>> {
    let mut statement = conn.prepare(queries::ACTIVE_POLICY)?;
    let table_iter = statement.query_map([], |row| {
        Ok({
            ActivePolicyRecord {
                client: row.get(0)?,
                client_type: row.get(1)?,
                policy_id: row.get(2)?,
            }
        })
    })?;

    let mut results = Vec::new();
    for record in table_iter {
        results.push(record?);
    }

    Ok(results)
}

fn read_access_overrides_table(conn: &Connection) -> Result<Vec<AccessOverridesRecord>> {
    let mut statement = conn.prepare(queries::ACCESS_OVERRIDES)?;
    let table_iter = statement.query_map([], |row| {
        Ok({
            AccessOverridesRecord {
                service: row.get(0)?,
            }
        })
    })?;

    let mut results = Vec::new();
    for record in table_iter {
        results.push(record?);
    }

    Ok(results)
}

fn read_expired_table(conn: &Connection) -> Result<Vec<ExpiredRecord>> {
    let mut statement = conn.prepare(queries::EXPIRED)?;
    let table_iter = statement.query_map([], |row| {
        Ok({
            ExpiredRecord {
                service: row.get(0)?,
                client: row.get(1)?,
                client_type: row.get(2)?,
                csreq: row.get(3)?,
                last_modified: row.get(4)?,
                expired_at: row.get(5)?,
            }
        })
    })?;

    let mut results = Vec::new();
    for record in table_iter {
        results.push(record?);
    }

    Ok(results)
}

fn read_access_table(conn: &Connection) -> Result<Vec<AccessRecord>> {
    let mut statement = conn.prepare(queries::ACCESS)?;
    let table_iter = statement.query_map([], |row| {
        Ok({
            AccessRecord {
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

    let mut results = Vec::new();
    for record in table_iter {
        results.push(record?);
    }

    Ok(results)
}

fn read_database(path: &str) -> Result<Database> {
    let conn = Connection::open(&path)?;

    Ok((
            Database { 
                admin: read_admin_table(&conn)?, 
                policies: read_policies_table(&conn)?, 
                active_policy: read_active_policy_table(&conn)?, 
                access: read_access_table(&conn)?, 
                access_overrides: read_access_overrides_table(&conn)?, 
                expired: read_expired_table(&conn)?, 
            }
    ))
}

fn parse_database(database: &Database) {
    println!("----=#=---- Admin Table Info ----=#=----");

    // for (i, record) in database.admin.iter().enumerate() {
    //     println!("---< Record #{} >---", i + 1);
    //     parse_record(record);
    // }

    println!("----=#=---- Access Table Info ----=#=----");

    for (i, record) in database.access.iter().enumerate() {
        println!("---< Access Record #{} >---", i + 1);
        parse_record(record);
    }
}

fn parse_record(record: &AccessRecord) {
    let client_type = match &record.client_type {
        0 => String::from("Bundle ID"),
        1 => String::from("Absolute Path"),
        _ => format!("Unknown client type: {:?}", &record.client_type), 
    };

    let auth_value = match &record.auth_value {
        0 => String::from("Denied"),
        1 => String::from("Unknown"),
        2 => String::from("Allowed"),
        3 => String::from("Limited"),
        _ => format!("Unknown auth value: {:?}", &record.auth_value),
    };

    let auth_reason = match &record.auth_reason {
        1 => String::from("User Consent"),
        2 => String::from("User Set"),
        3 => String::from("System Set"),
        4 => String::from("Service Policy"),
        5 => String::from("MDM Policy"),
        6 => String::from("Override Policy"),
        7 => String::from("Missing Usage String"),
        8 => String::from("Prompt Timeout"),
        9 => String::from("Preflight Unknown"),
        10 => String::from("Entitled"),
        11 => String::from("App Type Policy"),
        _ => format!("Unknown auth reason: {:?}", &record.auth_reason),
    };

    let csreq = match &record.csreq {
        Some(bytes) => format!("{:?} bytes", bytes.len()),
        None => String::from("None"),
    };

    let policy_id = match &record.policy_id {
        Some(id) => id.to_string(),
        None => String::from("None"),
    };

    let indirect_object_identifier_type = match &record.indirect_object_identifier_type {
        Some(0) => String::from("Bundle ID"),
        Some(1) => String::from("Absolute Path"),
        Some(_) => format!("Unknown indirect object identifier type: {:?}", &record.indirect_object_identifier_type),
        None => String::from("None"),
    };

    println!("Service: {}", record.service);
    println!("Client: {}", record.client);
    println!("Client Type: {}", client_type);
    println!("Auth Value: {}", auth_value);
    println!("Auth Reason: {}", auth_reason);
    println!("Auth Version: {}", record.auth_version);
    println!("Code Signing Req: {}", csreq);
    println!("Policy ID: {}", policy_id); 
    println!("Indirect Object Type: {}", indirect_object_identifier_type);
    println!("Indirect Object: {}", record.indirect_object_identifier);
}

fn main() -> Result<()>{
    let config: Config = parse_args(env::args());

    if config.help {
        display_help();
        return Ok(())
    }

    match config.input_file_path {
        Some(path) => {
            match read_header(&path) {
                Ok(header) => parse_header(&header),
                Err(err) => eprintln!("Failed to read header: {}", err)
            }

            match read_database(&path) {
                Ok(databse) => parse_database(&databse),   
                Err(err) => eprintln!("Failed to parse database: {}", err),
            }     
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

    Ok(())
}

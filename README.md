# Parser for MacOS TCC.db Files

This tool reads Apple MacOS TCC.db files located:
- `/Library/Application Support/com.apple.TCC/TCC.db` (system)
- `~/Library/Application Support/com.apple.TCC/TCC.db` (per user)

This tool reads those databases and turns the values into an easy to understand format.

## Options
- `-f, --file <PATH>` — Path to the TCC.db file to read
- `-o, --output <PATH>` — Path to write output (not yet implemented)
- `-h, --help` — Print help

## Building
cargo build --release

You will need full disk access for terminal to read TCC.db databases directly. Otherwise, copy the database somewhere else first.

## Example Output
```
----=#=---- Header Info ----=#=----
Header string: SQLite format 3
SQLite version: 3.45.1
Page size: 4096 bytes
Database size (pages): 13 pages
Database size (bytes): 53248 bytes
Text encoding: UTF-8
Journal mode: Rollback (legacy)
File change counter: 7
Schema cookie: 6
Schema format: 4
Freelist pages: 0 (first: 0)
Auto-vacuum: off
Incremental vacuum: off
User version: 0
Application ID: 0

----=#=---- Admin Table Info ----=#=----
---< Admin Record #1 >---
TCC database schema version: 20


----=#=---- Policies Table Info ----=#=----

----=#=---- Active Policy Table Info ----=#=----

----=#=---- Access Table Info ----=#=----
---< Access Record #1 >---
Service: kTCCServiceScreenCapture (Screen Recording)
Client: us.zoom.xos
Client Type: Bundle ID
Auth Value: Allowed
Auth Reason: User Set
Auth Version: 1
Code Signing Req: 36 bytes
Policy ID: None
Indirect Object Type: Bundle ID
Indirect Object: UNUSED

---< Access Record #2 >---
Service: kTCCServiceScreenCapture (Screen Recording)
Client: com.tinyspeck.slackmacgap
Client Type: Bundle ID
Auth Value: Allowed
Auth Reason: User Set
Auth Version: 1
Code Signing Req: 52 bytes
Policy ID: None
Indirect Object Type: Bundle ID
Indirect Object: UNUSED
```


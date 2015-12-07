# Throughputd
Network Traffic Monitoring Tool

Throughputd is a network traffic monitoring utility. It listens for IPv4 and IPv6 traffic and maintains records of how much data (in bytes) is going to and from each IP. This data is accumulated and saved to a sqlite database at a set interval. 

## Usage

```
throughputd [options...] [<interfaces>]
Valid options are:
```
    -t integer        Interval between writes in seconds (default: 5)
    -f path           Path to sqlite database (default: throughputd.db)
    -p path           Path to PID file (default: none)
    -a table          Name of database table (default: network_traffic)
    -d                Daemonize after starting (only if debugging disabled)
```

## Schema
The current schema for the output sqlite database is as follows:

```sql
CREATE TABLE IF NOT EXISTS network_traffic (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	ip TEXT NOT NULL,
	timestamp INTEGER NOT NULL,
	send_total INTEGER NOT NULL,
	recv_total INTEGER NOT NULL
);
```
Note: the table name can be altered with the -a option

## Compilation and Installation
The current dependencies of throuputd are gcc, libpcap, libpthread, and libsqlite3. After these libraries are installed on the system you can simply run `make` to build the binary. There is also a `make install` target to install the binary onto the system.

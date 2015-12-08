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

### Building Distribution Packages
Sample distribution packaging scripts for RPM based distributions (Fedora, CentOS/Red Hat Enterprise Linux, Mageia, and openSUSE) and Debian based distributions (Debian and Ubuntu) are provided. These can be used to generate native packages for supported Linux distributions.

#### RPM based distributions

1. Install `rpm-build` and the dependencies.

   * Fedora/CentOS/RHEL install commands:

      * Fedora 22 and newer: `sudo dnf install rpm-build sqlite-devel libpcap-devel @development-tools`

      * CentOS/RHEL + Fedora 21 and older: `sudo yum install rpm-build sqlite-devel libpcap-devel @development-tools`

   * Mageia install commands:

      * Mageia 5: `sudo urpmi rpm-build sqlite3-devel pcap-devel gcc`

      * Mageia 6: `sudo dnf install rpm-build sqlite3-devel pcap-devel gcc`

   * openSUSE Tumbleweed install commands:

      * `sudo zypper install rpm-build sqlite-devel libpcap-devel gcc`

2. Download the [tarball from GitHub](https://github.com/datto/throughputd/archive/master.tar.gz).

3. Construct your build root by running `mkdir -p ~/rpmbuild/{SOURCES,SPECS,SRPMS,RPMS,BUILD,BUILDROOT}`

4. Place the downloaded tarball into `~/rpmbuild/SOURCES`.

5. Extract the spec file (`throughputd.spec`) to `~/rpmbuild/SPECS`.

6. Change into `~/rpmbuild/SPECS` and run `rpmbuild -bb throughputd.spec` to generate the RPM.

7. Retrieve the built throughputd RPM from `~/rpmbuild/RPMS/<arch>` (where `<arch>` is your computer's architecture)

#### Debian based distributions

1. Install `build-essential` and the dependencies by running `sudo apt-get install build-essential libsqlite3-dev libpcap0.8-dev`

2. Download the [tarball from GitHub](https://github.com/datto/throughputd/archive/master.tar.gz).

3. Extract the tarball and change into the directory (typically `throughputd-master`) and run `dpkg-buildpackage -b -us -uc`

4. Retrieve the built throughputd Debian package

### Installing Distribution Packages

After building your package, you can install it by doing the following:

#### RPM based distributions

Fedora 22+/Mageia 6+: `sudo dnf install </path/to/built/rpm>`

Fedora 21 and older/CentOS/RHEL: `sudo yum install </path/to/built/rpm>`

Mageia 5: `sudo urpmi </path/to/built/rpm>`

openSUSE Tumbleweed: `sudo zypper install </path/to/built/rpm>`

#### Debian based distributions

Run the following commands:

1. `sudo dpkg -i </path/to/built/deb>`

2. If it complains about missing dependencies, then run `sudo apt-get install -f`

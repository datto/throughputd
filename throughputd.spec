Name:		throughputd
Version:	1.3.0
Release:	1%{?dist}
Summary:	A network traffic monitoring tool

# Mageia requires the Group to be specified
%if 0%{?mageia}
Group:		Networking/Other
%endif

# SUSE requires the Group to be specified
%if 0%{?suse_version}
Group:		Productivity/Networking/Other
%endif

%if 0%{?suse_version}
# SUSE uses a different license label format, based on SPDX
License:	GPL-2.0
%else
License:	GPLv2
%endif

URL:		https://github.com/datto/throughputd

# The Source has the name that GitHub will send the tarball to the browser as at the end
Source0:	https://github.com/datto/throughputd/archive/master.tar.gz#/%{name}-master.tar.gz

BuildRequires:	pkgconfig(sqlite3)

# libpcap doesn't provide pkgconfig file, so we must use package name
# This name is supported across Fedora, SUSE, and Mageia
BuildRequires:	libpcap-devel

# Provides the systemd macros
%if 0%{?suse_version}
BuildRequires: systemd-rpm-macros
%else
%if 0%{?mageia}
BuildRequires:	systemd-devel
%else
BuildRequires:	systemd-units
%endif
%endif

# Scriptlet requirements
Requires(post):     systemd
Requires(preun):    systemd
Requires(postun):   systemd

%description
Throughputd is a network traffic monitoring utility.
It listens for IPv4 and IPv6 traffic and maintains records
of how much data (in bytes) is going to and from each IP.
This data is accumulated and saved to an SQLite database at
a set interval.

%prep
%setup -q -n %{name}-master


%build
make %{?_smp_mflags}


%install
%make_install PREFIX=%{_prefix}

# Install systemd files
mkdir -p %{buildroot}%{_sysconfdir}/default
mkdir -p %{buildroot}%{_unitdir}
install -pm 0644 debian/%{name}.default %{buildroot}%{_sysconfdir}/default/%{name} 
install -pm 0444 debian/%{name}.service %{buildroot}%{_unitdir}/%{name}.service

# For ghost file data, so that RPM will remove them if they exist.
# These empty files will not actually be installed.
mkdir -p %{buildroot}%{_var}/lib/%{name}
touch %{buildroot}%{_var}/lib/%{name}/%{name}.sqlite


%files
%{_bindir}/%{name}
%{_unitdir}/%{name}.service
%config(noreplace) %{_sysconfdir}/default/%{name}
%ghost %{_var}/lib/%{name}
%if 0%{?fedora} || 0%{?rhel} || 0%{?mageia}
%license COPYING
%else
%doc COPYING
%endif
%doc README.md


%post
%systemd_post %{name}.service


%preun
%systemd_preun %{name}.service


%postun
%systemd_postun_with_restart %{name}.service


%changelog
* Thu Jan 12 2017 Tom Caputi <tcaputi@datto.com> - 1.2.0-1
- Added retry logic for transaction commits
* Thu Dec  8 2016 Tom Caputi <tcaputi@datto.com> - 1.2.0-1
- Fixed a bug where recording interval was inaccurate
* Mon Dec  7 2015 Neal Gompa <ngompa@datto.com> - 1.1.0-1
- Initial packaging

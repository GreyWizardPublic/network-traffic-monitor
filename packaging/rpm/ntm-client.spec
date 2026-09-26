# ntm-client.spec — repackages the ML-DSA-signed ntm-client release binary.
#
# Built by packaging/rpm/build-rpms.sh from build-linux/ (the CMake POST_BUILD
# step has already produced the binary and its NTMSIG 2 .sig). Nothing is
# compiled here.
#
# ⚠️ The binary must reach /usr/bin BYTE-IDENTICAL: its .sig covers the exact
# bytes, and ntm-client refuses to start (FATAL) if they differ. So every brp
# post-processing script — strip, debuginfo extraction, build-id rewriting — is
# disabled. build-rpms.sh re-extracts the payload and checks it with cmp.

%global debug_package %{nil}
%global __os_install_post %{nil}

Name:           ntm-client
Version:        %{ntm_version}
Release:        1%{?dist}
Summary:        Network Traffic Monitor client agent (packet capture and flow export)
License:        MIT
URL:            https://github.com/GreyWizardPublic/network-traffic-monitor
ExclusiveArch:  x86_64

Source0:        ntm-client-linux-amd64-%{version}
Source1:        ntm-client-linux-amd64-%{version}.sig
Source2:        ntm-client.service
Source3:        ntm-client.sysusers
Source4:        ntm-client.conf.example
Source5:        LICENSE
Source6:        LICENSES.md
Source7:        CLIENT_DEPLOYMENT.md

BuildRequires:  systemd-rpm-macros
# ML-DSA-65 (binary self-verification) needs OpenSSL >= 3.5.
Requires:       openssl-libs >= 1:3.5
%{?systemd_requires}

%description
ntm-client captures traffic with libpcap, aggregates flows and streams them
to an ntm-server over TLS. It runs as an unprivileged user with CAP_NET_RAW and
CAP_NET_ADMIN granted by its systemd unit.

Every binary verifies its own NTMSIG 2 signature (root keys -> delegation ->
build key) at startup; /usr/bin/ntm-client.sig must stay beside the binary.

%prep
cp -p %{SOURCE4} %{SOURCE5} %{SOURCE6} %{SOURCE7} .

%build
# Prebuilt and signed by CMake POST_BUILD; see the header.

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_bindir}/ntm-client
install -Dpm0644 %{SOURCE1} %{buildroot}%{_bindir}/ntm-client.sig
install -Dpm0644 %{SOURCE2} %{buildroot}%{_unitdir}/ntm-client.service
install -Dpm0644 %{SOURCE3} %{buildroot}%{_sysusersdir}/ntm-client.conf
install -dm0750 %{buildroot}%{_sysconfdir}/ntmclient

%post
%systemd_post ntm-client.service

%preun
%systemd_preun ntm-client.service

%postun
%systemd_postun_with_restart ntm-client.service

%files
%license LICENSE LICENSES.md
%doc ntm-client.conf.example CLIENT_DEPLOYMENT.md
%{_bindir}/ntm-client
%{_bindir}/ntm-client.sig
%{_unitdir}/ntm-client.service
%{_sysusersdir}/ntm-client.conf
# Read-only for the client (ReadOnlyPaths in the unit); holds its identity key.
%dir %attr(0750,root,ntmclient) %{_sysconfdir}/ntmclient

%changelog
* Sat Sep 26 2026 Fedora Linux Agent <support@code1one.com> - %{ntm_version}-1
- First RPM: trust v2 (root keys -> delegation -> build keys), #133.

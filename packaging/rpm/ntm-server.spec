# ntm-server.spec — repackages the ML-DSA-signed ntm-server release binary.
#
# Built by packaging/rpm/build-rpms.sh from build-linux/ (the CMake POST_BUILD
# step has already produced the binary and its NTMSIG 2 .sig). Nothing is
# compiled here.
#
# ⚠️ The binary must reach /usr/bin BYTE-IDENTICAL: its .sig covers the exact
# bytes, and ntm-server refuses to start (FATAL) if they differ. So every brp
# post-processing script — strip, debuginfo extraction, build-id rewriting — is
# disabled. build-rpms.sh re-extracts the payload and checks it with cmp.

%global debug_package %{nil}
%global __os_install_post %{nil}

Name:           ntm-server
Version:        %{ntm_version}
Release:        1%{?dist}
Summary:        Network Traffic Monitor server (ingestion, web dashboard, HTTPS API)
License:        MIT
URL:            https://github.com/GreyWizardPublic/network-traffic-monitor
ExclusiveArch:  x86_64

Source0:        ntm-server-linux-amd64-%{version}
Source1:        ntm-server-linux-amd64-%{version}.sig
Source2:        ntm-server.service
Source3:        ntm-server.sysusers
Source4:        ntm-server.conf.example
Source5:        LICENSE
Source6:        LICENSES.md
Source7:        SERVER_DEPLOYMENT.md

BuildRequires:  systemd-rpm-macros
# ML-DSA-65 (binary self-verification) needs OpenSSL >= 3.5.
Requires:       openssl-libs >= 1:3.5
%{?systemd_requires}

%description
ntm-server receives flow data from ntm-client agents over TLS, aggregates it,
and serves the web dashboard and the HTTPS API used by the NTMDashboard iOS app.

Every binary verifies its own NTMSIG 2 signature (root keys -> delegation ->
build key) at startup; /usr/bin/ntm-server.sig must stay beside the binary.

%prep
cp -p %{SOURCE4} %{SOURCE5} %{SOURCE6} %{SOURCE7} .

%build
# Prebuilt and signed by CMake POST_BUILD; see the header.

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_bindir}/ntm-server
install -Dpm0644 %{SOURCE1} %{buildroot}%{_bindir}/ntm-server.sig
install -Dpm0644 %{SOURCE2} %{buildroot}%{_unitdir}/ntm-server.service
install -Dpm0644 %{SOURCE3} %{buildroot}%{_sysusersdir}/ntm-server.conf
install -dm0750 %{buildroot}%{_sysconfdir}/ntm-server
install -dm0750 %{buildroot}%{_sharedstatedir}/ntm-server

%post
%systemd_post ntm-server.service

%preun
%systemd_preun ntm-server.service

%postun
%systemd_postun_with_restart ntm-server.service

%files
%license LICENSE LICENSES.md
%doc ntm-server.conf.example SERVER_DEPLOYMENT.md
%{_bindir}/ntm-server
%{_bindir}/ntm-server.sig
%{_unitdir}/ntm-server.service
%{_sysusersdir}/ntm-server.conf
# The server writes WebAuthn credential files into /etc/ntm-server
# (ReadWritePaths in the unit), so its account owns the directory.
%dir %attr(0750,ntm-server,ntm-server) %{_sysconfdir}/ntm-server
%dir %attr(0750,ntm-server,ntm-server) %{_sharedstatedir}/ntm-server

%changelog
* Sat Sep 26 2026 Fedora Linux Agent <support@code1one.com> - %{ntm_version}-1
- First RPM: trust v2 (root keys -> delegation -> build keys), #133.

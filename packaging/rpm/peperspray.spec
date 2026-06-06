%global debug_package %{nil}

Name:           peperspray
Version:        %{peperspray_version}
Release:        %{peperspray_release}%{?dist}
Summary:        Linux credential access guard for developer workstations
License:        MIT OR Apache-2.0
URL:            https://github.com/eresende/peperspray

Source0:        peperspray
Source1:        pepersprayd
Source2:        config.toml
Source3:        peperspray.logrotate
Source4:        pepersprayd.service
Source5:        LICENSE-MIT
Source6:        LICENSE-APACHE

BuildRequires:  systemd-rpm-macros
Requires:       systemd
Requires:       logrotate
Recommends:     libnotify

%description
peperspray is a Linux-first credential access guard. The daemon uses fanotify
permission events to deny protected credential-file reads unless explicit policy
allows the access.

%prep

%build

%install
install -d %{buildroot}%{_bindir}
install -d %{buildroot}%{_sysconfdir}/peperspray
install -d %{buildroot}%{_sysconfdir}/logrotate.d
install -d %{buildroot}%{_unitdir}
install -d %{buildroot}%{_localstatedir}/log/peperspray
install -d %{buildroot}%{_licensedir}/%{name}

install -m 0755 %{SOURCE0} %{buildroot}%{_bindir}/peperspray
install -m 0755 %{SOURCE1} %{buildroot}%{_bindir}/pepersprayd
install -m 0644 %{SOURCE2} %{buildroot}%{_sysconfdir}/peperspray/config.toml
install -m 0644 %{SOURCE3} %{buildroot}%{_sysconfdir}/logrotate.d/peperspray
install -m 0644 %{SOURCE4} %{buildroot}%{_unitdir}/pepersprayd.service
install -m 0644 %{SOURCE5} %{buildroot}%{_licensedir}/%{name}/LICENSE-MIT
install -m 0644 %{SOURCE6} %{buildroot}%{_licensedir}/%{name}/LICENSE-APACHE

%post
install -d -o root -g root -m 0755 %{_sysconfdir}/peperspray
install -d -o root -g root -m 0750 %{_localstatedir}/log/peperspray
if [ ! -e %{_localstatedir}/log/peperspray/events.jsonl ]; then
    install -o root -g root -m 0640 /dev/null %{_localstatedir}/log/peperspray/events.jsonl
fi
chown root:root %{_localstatedir}/log/peperspray/events.jsonl
chmod 0640 %{_localstatedir}/log/peperspray/events.jsonl
%systemd_post pepersprayd.service

%preun
%systemd_preun pepersprayd.service

%postun
%systemd_postun_with_restart pepersprayd.service
if [ "$1" -eq 0 ]; then
    rm -f %{_localstatedir}/log/peperspray/events.jsonl
    rmdir %{_localstatedir}/log/peperspray 2>/dev/null || true
fi

%files
%license %{_licensedir}/%{name}/LICENSE-MIT
%license %{_licensedir}/%{name}/LICENSE-APACHE
%{_bindir}/peperspray
%{_bindir}/pepersprayd
%config(noreplace) %{_sysconfdir}/peperspray/config.toml
%config(noreplace) %{_sysconfdir}/logrotate.d/peperspray
%{_unitdir}/pepersprayd.service
%dir %attr(0750,root,root) %{_localstatedir}/log/peperspray
%ghost %attr(0640,root,root) %{_localstatedir}/log/peperspray/events.jsonl

%changelog
* Fri Jun 05 2026 peperspray maintainers <maintainers@example.invalid> - 0.1.2-1
- Initial local RPM packaging.

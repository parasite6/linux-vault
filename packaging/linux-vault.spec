# Rust binaries do not produce a useful debugsource manifest.
%global debug_package %{nil}

Name:           linux-vault
Version:        0.1.0
Release:        1%{?dist}
Summary:        Lock a folder in your home

License:        GPL-3.0-only
URL:            https://github.com/parasite6/linux-vault
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  cargo
BuildRequires:  rust
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}
Requires:       7zip
Requires:       pinentry-qt

%description
linux-vault locks a folder. While it is unlocked the folder is ordinary
files. Lock packs it into one encrypted 7z archive. The root helper holds
the passphrase and locks open vaults on shutdown. lve is the command.

%prep
%setup -q

%build
# Fedora's %%build flags are for C. Cargo uses its own.
# CARGO_TARGET_DIR must not point outside this build, or %%install misses the binaries.
# The rpmbuild _topdir must be on disk (dist/rpmbuild or ~/rpmbuild). /tmp is RAM.
unset RUSTFLAGS
unset CARGO_ENCODED_RUSTFLAGS
unset CARGO_TARGET_DIR
cargo build --release --locked -p linux-vault-helper -p linux-vault-lve

%install
install -D -m 0755 target/release/linux-vault-helper %{buildroot}%{_libexecdir}/linux-vault-helper
install -D -m 0755 target/release/lve %{buildroot}%{_bindir}/lve
install -D -m 0644 packaging/systemd/linux-vault-helper.service %{buildroot}%{_unitdir}/linux-vault-helper.service
install -D -m 0644 packaging/dbus/org.linuxvault.Helper.service %{buildroot}%{_datadir}/dbus-1/system-services/org.linuxvault.Helper.service
install -D -m 0644 packaging/dbus/org.linuxvault.Helper.conf %{buildroot}%{_datadir}/dbus-1/system.d/org.linuxvault.Helper.conf
install -D -m 0644 packaging/polkit/org.linuxvault.policy %{buildroot}%{_datadir}/polkit-1/actions/org.linuxvault.policy
install -D -m 0644 packaging/sysctl/90-linux-vault-ptrace.conf %{buildroot}%{_sysctldir}/90-linux-vault-ptrace.conf
install -D -m 0644 packaging/systemd/logind.conf.d/linux-vault.conf %{buildroot}%{_prefix}/lib/systemd/logind.conf.d/linux-vault.conf

# %systemd_postun reloads unit state and does not restart the service.
# %systemd_postun_with_restart would drop every held passphrase on upgrade.
%post
%systemd_post linux-vault-helper.service
%sysctl_apply 90-linux-vault-ptrace.conf

%preun
%systemd_preun linux-vault-helper.service

%postun
%systemd_postun linux-vault-helper.service

%files
%license LICENSE
%{_bindir}/lve
%{_libexecdir}/linux-vault-helper
%{_unitdir}/linux-vault-helper.service
%{_datadir}/dbus-1/system-services/org.linuxvault.Helper.service
%{_datadir}/dbus-1/system.d/org.linuxvault.Helper.conf
%{_datadir}/polkit-1/actions/org.linuxvault.policy
%{_sysctldir}/90-linux-vault-ptrace.conf
%{_prefix}/lib/systemd/logind.conf.d/linux-vault.conf

%changelog
* Sat Sep 26 2026 parasite6 <myworkforstore@proton.me> - 0.1.0-1
- Package the helper, lve, and the shutdown and ptrace settings.

%bcond_without gnutls

%global gitdate     20200710
%global gitcommit   git_commit
%global gitshortcommit  %(c=%{gitcommit}; echo ${c:0:7})

# Macros needed by SELinux
%global selinuxtype targeted
%global moduletype  contrib
%global modulename  swtpm

Summary: TPM Emulator
Name:           swtpm
Version:        0.3.4
Release:        0.%{gitdate}git%{gitshortcommit}%{?dist}
License:        BSD
Url:            http://github.com/stefanberger/swtpm
Source0:        %{url}/archive/%{gitcommit}/%{name}-%{gitshortcommit}.tar.gz

BuildRequires:  automake
BuildRequires:  autoconf
BuildRequires:  libtool
BuildRequires:  libtpms-devel >= 0.6.0
BuildRequires:  glib2-devel
BuildRequires:  gmp-devel
BuildRequires:  expect
BuildRequires:  net-tools
BuildRequires:  openssl-devel
BuildRequires:  socat
BuildRequires:  python3
BuildRequires:  python3-twisted
BuildRequires:  softhsm
BuildRequires:  trousers >= 0.3.9
BuildRequires:  tpm-tools >= 1.3.8-6
%if %{with gnutls}
BuildRequires:  gnutls >= 3.1.0
BuildRequires:  gnutls-devel
BuildRequires:  gnutls-utils
BuildRequires:  libtasn1-devel
BuildRequires:  libtasn1
%endif
BuildRequires:  selinux-policy-devel
BuildRequires:  gcc
BuildRequires:  libseccomp-devel

Requires:       %{name}-libs = %{version}-%{release}
Requires:       libtpms >= 0.6.0
%{?selinux_requires}

%description
TPM emulator built on libtpms providing TPM functionality for QEMU VMs

%package        libs
Summary:        Private libraries for swtpm TPM emulators
License:        BSD

%description    libs
A private library with callback functions for libtpms based swtpm TPM emulator

%package        devel
Summary:        Include files for the TPM emulator's CUSE interface for usage by clients
License:        BSD
Requires:       %{name}-libs%{?_isa} = %{version}-%{release}

%description    devel
Include files for the TPM emulator's CUSE interface.

%package        tools
Summary:        Tools for the TPM emulator
License:        BSD
Requires:       swtpm = %{version}-%{release}
Requires:       trousers >= 0.3.9 tpm-tools >= 1.3.8-6 expect bash net-tools gnutls-utils

%description    tools
Tools for the TPM emulator from the swtpm package

%prep
%autosetup -n %{name}-%{gitcommit}

%build

NOCONFIGURE=1 ./autogen.sh
%configure \
%if %{with gnutls}
        --with-gnutls \
%endif
        --without-cuse

%make_build

%check
make %{?_smp_mflags} check

%install

%make_install
rm -f $RPM_BUILD_ROOT%{_libdir}/%{name}/*.{a,la,so}
rm -f $RPM_BUILD_ROOT%{_mandir}/man8/swtpm-create-tpmca.8*
rm -f $RPM_BUILD_ROOT%{_datadir}/%{name}/swtpm-create-tpmca

%post
for pp in /usr/share/selinux/packages/swtpm.pp \
          /usr/share/selinux/packages/swtpm_svirt.pp; do
  %selinux_modules_install -s %{selinuxtype} ${pp}
done

%postun
if [ $1 -eq  0 ]; then
  for p in swtpm swtpm_svirt; do
    %selinux_modules_uninstall -s %{selinuxtype} $p
  done
fi

%posttrans
%selinux_relabel_post -s %{selinuxtype}

%ldconfig_post libs
%ldconfig_postun libs

%files
%license LICENSE
%doc README
%{_bindir}/swtpm
%{_mandir}/man8/swtpm.8*
%{_datadir}/selinux/packages/swtpm.pp
%{_datadir}/selinux/packages/swtpm_svirt.pp

%files libs
%license LICENSE
%doc README

%dir %{_libdir}/%{name}
%{_libdir}/%{name}/libswtpm_libtpms.so.0
%{_libdir}/%{name}/libswtpm_libtpms.so.0.0.0

%files devel
%dir %{_includedir}/%{name}
%{_includedir}/%{name}/*.h
%{_mandir}/man3/swtpm_ioctls.3*

%files tools
%doc README
%{_bindir}/swtpm_bios
%if %{with gnutls}
%{_bindir}/swtpm_cert
%endif
%{_bindir}/swtpm_setup
%{_bindir}/swtpm_setup.sh
%{_bindir}/swtpm_ioctl
%{_mandir}/man8/swtpm_bios.8*
%{_mandir}/man8/swtpm_cert.8*
%{_mandir}/man8/swtpm_ioctl.8*
%{_mandir}/man8/swtpm-localca.conf.8*
%{_mandir}/man8/swtpm-localca.options.8*
%{_mandir}/man8/swtpm-localca.8*
%{_mandir}/man8/swtpm_setup.8*
%{_mandir}/man8/swtpm_setup.conf.8*
%{_mandir}/man8/swtpm_setup.sh.8*
%config(noreplace) %{_sysconfdir}/swtpm_setup.conf
%config(noreplace) %{_sysconfdir}/swtpm-localca.options
%config(noreplace) %{_sysconfdir}/swtpm-localca.conf
%dir %{_datadir}/swtpm
%{_datadir}/swtpm/swtpm-localca
%attr( 755, tss, tss) %{_localstatedir}/lib/swtpm-localca

%changelog
* Fri Jul 10 2020 Stefan Berger <stefanb@linux.ibm.com> - 0.3.2
- v0.3.2 release

* Mon Mar 30 2020 Stefan Berger <stefanb@linux.ibm.com> - 0.3.1-20200218git7b30a54
- v0.3.1 release

* Mon Feb 17 2020 Stefan Berger <stefanb@linux.ibm.com> - 0.3.0-20200218git38f36f3
- v0.3.0 release

* Fri Jul 19 2019 Stefan Berger <stefanb@linux.ibm.com> - 0.2.0-20190716git817d3a8
- v0.2.0 release

* Mon Feb 4 2019 Stefan Berger <stefanb@linux.vnet.ibm.com> - 0.1.0-0.20190204git2c25d13
- v0.1.0 release

* Mon Sep 17 2018 Stefan Berger <stefanb@linux.vnet.ibm.com> - 0.1.0-0.20180918git67d7ea3
- Created initial version of rpm spec files
- Version is now 0.1.0
- Bugzilla for this spec: https://bugzilla.redhat.com/show_bug.cgi?id=1611829

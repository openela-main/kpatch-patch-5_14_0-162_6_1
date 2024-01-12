# Set to 1 if building an empty subscription-only package.
%define empty_package		0

#######################################################
# Only need to update these variables and the changelog
%define kernel_ver	5.14.0-162.6.1.el9_1
%define kpatch_ver	0.9.7
%define rpm_ver		1
%define rpm_rel		4

%if !%{empty_package}
# Patch sources below. DO NOT REMOVE THIS LINE.
#
# https://bugzilla.redhat.com/2141637
Source100: CVE-2022-2959.patch
#
# https://bugzilla.redhat.com/2142785
Source101: CVE-2022-2964.patch
#
# https://bugzilla.redhat.com/2147591
Source102: CVE-2022-4139.patch
#
# https://bugzilla.redhat.com/2143187
Source103: CVE-2022-43945.patch
#
# https://bugzilla.redhat.com/2153007
Source104: CVE-2022-3564.patch
#
# https://bugzilla.redhat.com/2152599
Source105: CVE-2022-4378.patch
#
# https://bugzilla.redhat.com/2153157
Source106: CVE-2022-4379.patch
#
# https://bugzilla.redhat.com/2161747
Source107: CVE-2023-0179.patch
#
# https://bugzilla.redhat.com/2156383
Source108: CVE-2022-4744.patch
#
# https://bugzilla.redhat.com/2163415
Source109: CVE-2023-0266.patch
#
# https://bugzilla.redhat.com/2165362
Source110: CVE-2023-0386.patch
# End of patch sources. DO NOT REMOVE THIS LINE.
%endif

%define sanitized_rpm_rel	%{lua: print((string.gsub(rpm.expand("%rpm_rel"), "%.", "_")))}
%define sanitized_kernel_ver   %{lua: print((string.gsub(string.gsub(rpm.expand("%kernel_ver"), '.el9_?\%d?', ""), "%.", "_")))}
%define kernel_ver_arch        %{kernel_ver}.%{_arch}

Name:		kpatch-patch-%{sanitized_kernel_ver}
Version:	%{rpm_ver}
Release:	%{rpm_rel}%{?dist}

%if %{empty_package}
Summary:	Initial empty kpatch-patch for kernel-%{kernel_ver_arch}
%else
Summary:	Live kernel patching module for kernel-%{kernel_ver_arch}
%endif

Group:		System Environment/Kernel
License:	GPLv2
ExclusiveArch:	x86_64 ppc64le

Conflicts:	%{name} < %{version}-%{release}

Provides:	kpatch-patch = %{kernel_ver_arch}
Provides:	kpatch-patch = %{kernel_ver}

%if !%{empty_package}
Requires:	systemd
%endif
Requires:	kpatch >= 0.6.1-1
Requires:	kernel-uname-r = %{kernel_ver_arch}

%if !%{empty_package}
BuildRequires:	patchutils
BuildRequires:	kernel-devel = %{kernel_ver}
BuildRequires:	kernel-debuginfo = %{kernel_ver}

# kernel build requirements, generated from:
#   % rpmspec -q --buildrequires kernel.spec | sort | awk '{print "BuildRequires:\t" $0}'
# with arch-specific packages moved into conditional block
BuildRequires:	bash
BuildRequires:	bc
BuildRequires:	binutils
BuildRequires:	bison
BuildRequires:	bpftool
BuildRequires:	bzip2
BuildRequires:	coreutils
BuildRequires:	diffutils
BuildRequires:	dwarves
BuildRequires:	elfutils
BuildRequires:	elfutils-devel
BuildRequires:	findutils
BuildRequires:	flex
BuildRequires:	gawk
BuildRequires:	gcc
BuildRequires:	gcc-c++
BuildRequires:	gcc-plugin-devel
BuildRequires:	git-core
BuildRequires:	glibc-static
BuildRequires:	gzip
BuildRequires:	hmaccalc
BuildRequires:	hostname
BuildRequires:	kernel-rpm-macros >= 185-9
BuildRequires:	kmod
BuildRequires:	m4
BuildRequires:	make
BuildRequires:	net-tools
BuildRequires:	nss-tools
BuildRequires:	openssl
BuildRequires:	openssl-devel
BuildRequires:	patch
BuildRequires:	perl-Carp
BuildRequires:	perl-devel
BuildRequires:	perl-generators
BuildRequires:	perl-interpreter
BuildRequires:	python3-devel
BuildRequires:	redhat-rpm-config
BuildRequires:	rpm-build
BuildRequires:	system-sb-certs
BuildRequires:	tar
BuildRequires:	which
BuildRequires:	xz

%ifarch x86_64
BuildRequires:	pesign >= 0.10-4
%endif

Source0:	https://github.com/dynup/kpatch/archive/v%{kpatch_ver}.tar.gz

Source10:	kernel-%{kernel_ver}.src.rpm

# kpatch-build patches
Patch1: v0.9.7-backport-MR-1314-create-diff-object-fix-__UNI.patch
Patch2: v0.9.7-backport-MR-1315-Static-call-fixes.patch

%global _dupsign_opts --keyname=rhelkpatch1

%define builddir	%{_builddir}/kpatch-%{kpatch_ver}
%define kpatch		%{_sbindir}/kpatch
%define kmoddir 	%{_usr}/lib/kpatch/%{kernel_ver_arch}
%define kinstdir	%{_sharedstatedir}/kpatch/%{kernel_ver_arch}
%define patchmodname	kpatch-%{sanitized_kernel_ver}-%{version}-%{sanitized_rpm_rel}
%define patchmod	%{patchmodname}.ko

%define _missing_build_ids_terminate_build 1
%define _find_debuginfo_opts -r
%undefine _include_minidebuginfo
%undefine _find_debuginfo_dwz_opts

%description
This is a kernel live patch module which can be loaded by the kpatch
command line utility to modify the code of a running kernel.  This patch
module is targeted for kernel-%{kernel_ver}.

%prep
%autosetup -n kpatch-%{kpatch_ver} -p1

%build
kdevdir=/usr/src/kernels/%{kernel_ver_arch}
vmlinux=/usr/lib/debug/lib/modules/%{kernel_ver_arch}/vmlinux

# kpatch-build
make -C kpatch-build

# patch module
for i in %{sources}; do
	[[ $i == *.patch ]] && patch_sources="$patch_sources $i"
done
export CACHEDIR="%{builddir}/.kpatch"
kpatch-build/kpatch-build -n %{patchmodname} -r %{SOURCE10} -v $vmlinux --skip-cleanup $patch_sources || { cat "${CACHEDIR}/build.log"; exit 1; }


%install
installdir=%{buildroot}/%{kmoddir}
install -d $installdir
install -m 755 %{builddir}/%{patchmod} $installdir


%files
%{_usr}/lib/kpatch


%post
%{kpatch} install -k %{kernel_ver_arch} %{kmoddir}/%{patchmod}
chcon -t modules_object_t %{kinstdir}/%{patchmod}
sync
if [[ %{kernel_ver_arch} = $(uname -r) && "${LEAPP_IPU_IN_PROGRESS}" != "8to9" ]]; then
	cver="%{rpm_ver}_%{rpm_rel}"
	pname=$(echo "kpatch_%{sanitized_kernel_ver}" | sed 's/-/_/')

	lver=$({ %{kpatch} list | sed -nr "s/^${pname}_([0-9_]+)\ \[enabled\]$/\1/p"; echo "${cver}"; } | sort -V | tail -1)

	if [ "${lver}" != "${cver}" ]; then
		echo "WARNING: at least one loaded kpatch-patch (${pname}_${lver}) has a newer version than the one being installed."
		echo "WARNING: You will have to reboot to load a downgraded kpatch-patch"
	else
		%{kpatch} load %{patchmod}
	fi
fi
exit 0


%postun
%{kpatch} uninstall -k %{kernel_ver_arch} %{patchmod}
sync
exit 0

%else
%description
This is an empty kpatch-patch package which does not contain any real patches.
It is only a method to subscribe to the kpatch stream for kernel-%{kernel_ver}.

%files
%doc
%endif

%changelog
* Mon Mar 27 2023 Yannick Cote <ycote@redhat.com> [1-4.el9_1]
- kernel: FUSE filesystem low-privileged user privileges escalation [2165362] {CVE-2023-0386}

* Sat Mar 18 2023 Yannick Cote <ycote@redhat.com> [1-3.el9_1]
- ALSA: pcm: Move rwsem lock inside snd_ctl_elem_read to prevent UAF [2163415] {CVE-2023-0266}
- EMBARGOED CVE-2022-4744 kernel: tun: avoid double free in tun_free_netdev [2156383] {CVE-2022-4744}

* Tue Feb 14 2023 Yannick Cote <ycote@redhat.com> [1-2.el9_1]
- kernel: Netfilter integer overflow vulnerability in nft_payload_copy_vlan [2161747] {CVE-2023-0179}
- kernel: use-after-free in __nfs42_ssc_open() in fs/nfs/nfs4file.c leading to remote Denial of Service attack [2153157] {CVE-2022-4379}
- kernel: a stack overflow in do_proc_dointvec and proc_skip_spaces [2152599] {CVE-2022-4378}
- kernel: use-after-free caused by l2cap_reassemble_sdu() in net/bluetooth/l2cap_core.c [2153007] {CVE-2022-3564}

* Wed Jan 04 2023 Yannick Cote <ycote@redhat.com> [1-1.el9_1]
- kernel: nfsd buffer overflow by RPC message over TCP with garbage data [2143187] {CVE-2022-43945}
- kernel: i915: Incorrect GPU TLB flush can lead to random memory access [2147591] {CVE-2022-4139}
- kernel: memory corruption in AX88179_178A based USB ethernet device. [2142785] {CVE-2022-2964}
- kernel: watch queue race condition can lead to privilege escalation [2141637] {CVE-2022-2959}

* Mon Oct 24 2022 Yannick Cote <ycote@redhat.com> [0-0.el9]
- An empty patch to subscribe to kpatch stream for kernel-5.14.0-162.6.1.el9_1 [2137424]

# Change Log
All notable changes to this project are documented in this file.

The format is based on [Keep a CHANGELOG](http://keepachangelog.com/)

## Unreleased
### Added
- Integration test script and build support to execute integration tests
against a physical TPM2 device on the build platform.
### Removed
- Command line option --fail-on-loaded-trans.

## 1.2.0 - 2017-12-08
### Added
- Check SAPI library is < 2.0.0 (API change upstream).
- Abstract class for IPC frontend implementation. Port dbus code from main
module to class inheriting from the IpcFrontend.
- SELinux policy module to work around policy in Fedora.
- Limit maximum number of active sessions per connection with '--max-sessions'.
- Flush all transient objects and sessions on daemon start with '--flush-all'.
- Allow passing of sessions across connections with ContextSave / Load.
### Changed
- Set valgrind leak-check flag to 'full'.
- Client / server communication uses PF_LOCAL sockets instead of pipes.
- bootstrap script now creates VERSION file from 'git describe'. Autoconf gets
version string from it, automake distributes it in 'distcheck'.
- Test harness upgraded to simulator version 974.
- Unit tests upgraded to the 1.x cmocka API.
- Replace use of thread in CommandSource with GMainLoop.
- Replace use of file descriptors with GIO streams.
- Separate 'dispose' and 'finalize' functions in each object.
- Move creation of FDs from connection_new to calling context (dependency
inversion).
### Fixed
- Unref the GUnixFDList returned by GIO / dbus in the TCTI init function.
This fixes a memory leak in the TCTI library.

## 1.1.1 - 2017-08-25
### Added
- Systemd 'preset' file and corresponding options to the configure script.
- Option to configure script to allow the addition of a string prefix to
the udev rules file name.
### Changed
- Replace use of sigaction with g_unix_signal_* stuff from glib.
- Rewrite of INSTALL.md including info on custom configure script options.
- Default value for --with-simulatorbin configure option has been removed.
New default behavior is to disable integration tests.
- CommandSource will no longer reject commands without parameters.
- Unit tests updated to use cmocka v1.0.0 API.
- Integration tests now run daemon under valgrind memcheck and fail when
errors are found.
- CommandSource now tracks max FD in set of client FDs to prevent unnecessary
iterations over FD_SETSIZE fds.
### Fixed
- Release tarballs now include essential files missing from 1.1.0 release.
- Robustness fixes in CommandSource.
- Stability fixes in Tpm2Command handling that could result in crashes.
- int-log-compiler.sh now fails if required binaries not found.
- check-valgrind target now depends on check_PROGRAMS to ensure daemon is
built before tests are run.
- NULL deref bug in TCTI.
- Mishandling of short reads in util module.
- Race condition on daemon shutdown that could cause deadlock.
- Several logic errors & data initialization for more strict compiler
versions.

## 1.1.0 - 2017-07-01
### Added
- Integration test harness supporting parallel execution using automake
- Environment variables TABRMD_TEST_BUS_TYPE and TABRMD_TEST_BUS_NAME to
control D-Bus type and name selection respectively in the integration test
harness.
- tss2_tcti_tabrmd_init_full function to libtcti-tabrmd to allow for selection
of D-Bus bus type and name used by tpm2-abrmd instance.
- Command line option --dbus-name to control the name claimed by the daemon
on the D-Bus.
- Command line option --prng-seed-file to allow configuration of seed source.
The default is /dev/urandom. The only use of the PRNG in the daemon is to
differentiate between the connections held by a single client.
infrastructure.
- Lots of new unit and integration tests.
- Automated coverity static analysis scans.
### Changed
- New configuration option to specify location of simulator binary (required
for integration tests).
- Lots of documentation updates (README.md / INSTALL.md)
- Travis-CI now executes all tests under valgrind / memcheck.
### Fixed
- Deconflict command line options: -t for TCTI selection, -a to fail if
transient objects are already loaded in the TPM.
- Clients can hold multiple TCTI connections again (fixed regression).
- Syslog log handler now only shows info & debug messages when
G_MESSAGES_DEBUG is set to 'all'.
- Free memory in error path in integration test harness.
- distcheck make target now works.

## 1.0.0 - 2017-05-21
### Added
- Everything - initial release.

#!/usr/bin/env bash
# portable-test-packages prints the package list that CI's windows-test and macos-test jobs
# hand to `go test`: every package that builds for the current GOOS, minus a short skip list.
# The reason for skipping is not the same for every package or every GOOS: see the comment
# above the list below for which runner each failure is confirmed on.
#
# The list used to be written out in .github/workflows/ci.yml, once per job. A package added
# later was covered on Linux by `go test ./...` but stayed invisible on Windows and macOS
# until someone remembered to add it to both lists, so the guarantee those two jobs exist for
# had a hole that was easy to open and hard to notice. Computing the list closes it: a package
# is tested on Windows and macOS as soon as it exists.
#
# `go test ./...` is still not what the jobs run, for the reason that put an explicit list
# there in the first place. Skipping a package here is not a claim that it fails on both
# jobs; the comment above the list says which runner each failure is confirmed on. Naming
# the packages here limits the exclusion to those packages, instead of excluding everything
# that nobody added to a list.
#
# The Linux-only packages need no naming: `go list ./...` leaves out a directory whose files
# are all excluded by a `//go:build linux` tag, which is why internal/vpsd,
# internal/dataplane/linuxkernel and internal/platform/linux do not appear for GOOS=windows
# or GOOS=darwin. What keeps a file added to one of them without that tag from breaking those
# builds is the `go build ./...` and `go vet ./...` steps of the jobs themselves, not this
# script.
#
# To remove a package from the skip list, fix the test and delete it from the list below. To
# add one, name the test that fails and why, so that the next reader can tell a real platform
# limit from a test nobody has got to yet.
set -euo pipefail

# The skip list is not the same on every GOOS, because the failures below are not the same
# on every GOOS:
#
# internal/dataplane/userspace: TestPrepareBindFailureIsFailClosed fails on native Windows,
#   recorded in issue #109. Its subpackages relay, tunnel and utun pass there and are not
#   excluded.
# internal/vpsd/store: TestOpenTightensExistingModesTo0600 and TestNarrowModeKeepsOwnerBits
#   fail on native Windows, recorded in issue #109. Both compare file modes against 0o600 and
#   0o400 with no Windows branch, and Windows does not keep POSIX permission bits.
# tools/labhost: TestRunLockNamesItsHolder fails on native Windows, recorded in issue #109. It
#   names the lock's holder through holderSuffix, which reads /proc/<pid>/comm, so it assumes
#   Linux, not merely POSIX: macOS has no /proc either, so it is expected to fail there too,
#   though that expectation is untested.
#
# A macos-latest run confirmed internal/vpsd/store and internal/dataplane/userspace pass on
# macOS, the three tests named above included, so the macOS skip list carries only
# tools/labhost.
case "$(go env GOOS)" in
windows)
	skip='^github\.com/rahanahu/wgft/(internal/dataplane/userspace|internal/vpsd/store|tools/labhost)$'
	;;
darwin)
	skip='^github\.com/rahanahu/wgft/tools/labhost$'
	;;
*)
	# windows-test and macos-test are the only callers, but a skip list built for a failure
	# specific to one of those two GOOS values would be wrong to apply anywhere else, so a
	# third GOOS excludes nothing.
	skip='$^'
	;;
esac

# go list runs on its own line, not at the head of a pipe, so that its failure stops the
# script under set -e instead of leaving a partial list on stdout. An empty result fails
# too: it would hand `go test` no packages, which tests the current directory instead.
all=$(go list ./...)
pkgs=$(grep -Ev "$skip" <<<"$all" || true)
if [ -z "$pkgs" ]; then
	echo "portable-test-packages: go list returned no packages to test" >&2
	exit 1
fi
printf '%s\n' "$pkgs"

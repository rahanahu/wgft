#!/usr/bin/env bash
# portable-test-packages prints the package list that CI's windows-test and macos-test jobs
# hand to `go test`: every package that builds for the current GOOS, minus the ones with
# known pre-existing failures there.
#
# The list used to be written out in .github/workflows/ci.yml, once per job. A package added
# later was covered on Linux by `go test ./...` but stayed invisible on Windows and macOS
# until someone remembered to add it to both lists, so the guarantee those two jobs exist for
# had a hole that was easy to open and hard to notice. Computing the list closes it: a package
# is tested on Windows and macOS as soon as it exists.
#
# `go test ./...` is still not what the jobs run, for the reason that put an explicit list
# there in the first place. The packages named below fail on those runners today for reasons
# that predate this script, and running them would turn both jobs red for every change.
# Naming them here limits the exclusion to those packages, instead of excluding everything
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

# Each of the three was recorded in issue #109 as failing on native Windows, and none of the
# failures comes from a build tag:
#
# internal/dataplane/userspace: TestPrepareBindFailureIsFailClosed. Its subpackages relay,
#   tunnel and utun pass and are not excluded.
# internal/vpsd/store: TestOpenTightensExistingModesTo0600 and TestNarrowModeKeepsOwnerBits.
#   Both compare file modes against 0o600 and 0o400 with no Windows branch, and Windows does
#   not keep POSIX permission bits.
# tools/labhost: TestRunLockNamesItsHolder. It names the lock's holder through holderSuffix,
#   which reads /proc/<pid>/comm, so it assumes Linux, not merely POSIX: macOS has no /proc
#   either.
#
# The same list is used on macOS. store and internal/dataplane/userspace may well pass
# there, which is not confirmed; neither ran on macOS before this script either.
skip='^github\.com/rahanahu/wgft/(internal/dataplane/userspace|internal/vpsd/store|tools/labhost)$'

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

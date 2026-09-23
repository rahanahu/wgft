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

# internal/dataplane/userspace: TestPrepareBindFailureIsFailClosed fails on native Windows
#   (issue #109). Its subpackages relay, tunnel and utun pass and are not excluded.
# internal/vpsd/store: its mode tests assert POSIX permission bits, which Windows does not
#   carry.
# tools/labhost: POSIX assumptions in its tests.
skip='^github\.com/rahanahu/wgft/(internal/dataplane/userspace|internal/vpsd/store|tools/labhost)$'

go list ./... | grep -Ev "$skip"

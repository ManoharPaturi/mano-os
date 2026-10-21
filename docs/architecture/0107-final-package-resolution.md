# 0107: Consistent final package resolution

A package forecast must describe one final dependency solution. Python-APT's
`mark_install(auto_fix=True)` runs the dependency resolver; later marks can
change earlier package state. Record requested installed/candidate versions
only after all requested names are marked and the final cache has no broken
dependencies. Refuse a solution that removes a requested package, drops its
candidate, or leaves its candidate unavailable from the signed catalog.

The shared result validator independently checks requested rows against the
final change set. Every requested transition must have a matching change row,
including identical installed and candidate versions. A requested package
without a change must already have its candidate installed. Requested removals
are invalid, while dependency removals remain explicitly represented. Operation
labels must agree with the presence/equality of the recorded versions: a new
install has no installed version, a reinstall retains the same version, and
upgrade/downgrade require an existing, different version. This check does not
implement Debian version ordering or independently re-resolve dependencies.

The existing native PAM/public SDK forecast probe now checks requested/change
agreement in both the dependency and installed-package cases. Local regression
fixtures exercise later-mark candidate changes/removal/unavailability and
malformed or missing transitions. Actual signed inputs, native isolation/Stop,
runtime package, stock reboot, recovery and GUI acceptance remain required on
the final CI head. Local fake-cache tests do not establish native APT behavior.

This preserves the forecast-only API and wire schema. It does not authorize
installation or prove privileged apply, peak-space sufficiency, production
maintainer-script interruption, or product completion.

Primary interface: [Python-APT package marking and candidate state](https://apt-team.pages.debian.net/python-apt/library/apt.package.html).

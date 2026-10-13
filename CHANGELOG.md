# Changelog

Everything worth knowing about a release of Arandu Inspect is recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

A published module version is immutable: Go serves it from the proxy forever, so
a release is corrected by another release and never by moving a tag.

## [Unreleased]

## [0.1.0] - 2026-10-13

The first release: an operator inspects a user's account without signing out.

### Added

- `POST /inspect/users/{id}` (`inspect.start`): the session is rotated to the
  account's owner with the operator acting (hesape `auth.ImpersonateActing`);
  the visit is an `Inspection` with a deadline and the entry
  `inspection.started` in the `inspect` activity log.
- `POST /inspect/leave` (`inspect.leave`, the route hesape's `view.New` links
  the way back by): back to the operator's own session, the inspection closed,
  `inspection.left` recorded.
- `Guard()`: past the deadline the operator is taken back and
  `inspection.expired` recorded.
- `GET /inspect/history` and `InspectService.OpenNow`: who went into which
  account, and who is inside one now.
- The role `inspect.operator`; an account that carries it is never inspected,
  nobody inspects from inside an account, and only the operator who opened an
  inspection closes it.
- The actions `InspectStart`, `InspectLeave` and `InspectHistory`.
- The migration `20261013_0001_create_inspections`.


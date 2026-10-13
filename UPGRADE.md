# Upgrade Guide

## Unreleased

## v0.1.0

The first release. Install arandu-activitylog v0.3.0 beside it (hesape v0.57.0
or newer comes with it), wire it in `bootstrap/app.go` as the README shows,
mount `Guard()` after `RequireAuth` on the routes reachable from inside an
account, run `aru migrate`, draw the bar from `view.Inspection` in the
application's layout, and give the operators the role `inspect.operator`
through arandu-permission.

<p align="center">
  <img src=".github/logo.svg" alt="Arandu" width="180">
</p>

# Arandu Inspect

> **Renamed.** This package is now
> [hyz-is/arandu-impersonate](https://github.com/hyz-is/arandu-impersonate),
> which follows laravel-impersonate's names and adds `Protect()` and
> `CanBeImpersonated`. This repository is archived; install the new one.


An operator goes into a user's account from the admin, **without signing out
of their own**, acts there as the user — sees what the user sees, changes what
the user can change — and comes back with one click. Every visit has a
deadline, and everything is recorded in
[arandu-activitylog](https://github.com/hyz-is/arandu-activitylog) under the
operator's name, with the account it was done in.

It is the "inspecionar" of the operator consoles the team runs, made safe:
who may inspect is a Policy, an operator's own account and another operator's
are refused, nobody inspects from inside an account, and nothing done inside
goes unlogged.

## How it works

- `POST /inspect/users/{id}` — the operator goes into the account. The session
  is rotated to the account's owner with the operator kept as the one acting
  (hesape `auth.ImpersonateActing`), so the very same browser is now inside the
  account and every Grant writes as the owner would. The visit is recorded as
  an inspection with a deadline (one hour by default), and as the entry
  `inspection.started` in the `inspect` log.
- Inside the account, every entry the application records names **the
  operator** as its causer and carries the `impersonation` property — `by`,
  `on_behalf_of`, `mode: acting` — which arandu-activitylog v0.3.0 adds by
  itself.
- `POST /inspect/leave` (route name `inspect.leave`) — the operator comes back:
  the session is rotated to their own subject, the inspection is closed and
  `inspection.left` is recorded.
- `Guard()` — past the deadline, the next request inside the account takes the
  operator back, closes the inspection and records `inspection.expired`.
- `GET /inspect/history` — the inspections, newest first, for an operator.

## The bar

Every page built with `view.New` (hesape v0.57.0) knows it is drawn for an
operator inside somebody's account and where the way back is. The
application's layout draws the bar from `view.Inspection`:

```go
@if(inspecting(.))
	<div class="..." role="status">
		Você está na conta deste usuário como administrador.
		<form method="post" action="{{ leaveLink(.) }}">@csrf<button>Voltar ao administrador</button></form>
	</div>
@endif
```

with, in the layout's `@go` block:

```go
func inspecting(d hview.Layout) bool {
	i, ok := d.(hview.Inspection)
	return ok && i.IsInspecting()
}
```

## Install

```bash
go get github.com/hyz-is/arandu-activitylog@v0.3.0
go get github.com/hyz-is/arandu-inspect
```

It needs hesape v0.57.0 or newer.

## Wire it

In `bootstrap/app.go`, after the session store and the activity log exist:

```go
	inspectModule, err := inspect.New(inspect.Config{
		Targets:  inspect.TargetsFunc(users.InspectTarget), // the account as its owner signs in
		Activity: activityModule.Logger(),
		Landing:  "/painel",
		Return:   "/admin/usuarios",
	}, db, sessions)
	if err != nil {
		return App{}, err
	}
```

register `inspectModule` in `k.Register(...)`, mount the guard after
`RequireAuth` on the routes reachable from inside an account:

```go
	panel := r.Group("/painel", middleware.RequireAuth(sessions), inspectModule.Guard())
```

and run `aru migrate`. `Targets` answers the subject the account's owner signs
in as — identifier, tenant, roles, actions — because the package keeps no
users.

## Give people access

`inspect.operator` is the role that goes into accounts and reads the history;
the application gives it through
[arandu-permission](https://github.com/hyz-is/arandu-permission). An account
that carries the role is never inspected.

## Configuration

| field | required | meaning |
| --- | --- | --- |
| `Targets` | yes | loads the account an operator goes into. |
| `Activity` | yes | arandu-activitylog's logger. |
| `Prefix` | no | where the routes are mounted. Defaults to `/inspect`. |
| `Landing` | no | where the operator lands inside the account. Defaults to `/`. |
| `Return` | no | where they land back in their own. Defaults to `/`. |
| `TTL` | no | how long a visit lasts. Defaults to one hour; at most 12 hours. |
| `UserType` | no | the kind the activity log names accounts by. Defaults to `user`. |

## The data path

`Inspection` embeds `model.Model` and declares its table beside it.
`aru model:build` generates `InspectionQuery.go` with `Inspections(db)`,
committed and never edited by hand; `aru model:build --check` fails when it is
out of date. `InspectService` follows
`validate -> security.Authorize -> Grant -> Model terminal` in every exported
method, which the unit suite audits, and every route sits behind
`RequireAuth`.

## Example

```bash
go run -tags example ./example
```

It opens SQLite in a temporary directory, migrates arandu-activitylog and this
package, and drives one browser: the operator goes into a user's account,
changes a setting there, comes back, and the activity log is printed with every
entry under the operator's name. It leaves nothing behind. The build tag is
there so that installing this package never compiles it.

## Tests

```bash
GOWORK=off go test ./... -race
```

The feature suite runs the whole visit in one browser against SQLite: going
in, acting as the owner, coming back, the deadline, and every refusal, with
the activity log's entries checked; the rules were checked by mutation.

## Licence

MIT. See [LICENSE.md](LICENSE.md).

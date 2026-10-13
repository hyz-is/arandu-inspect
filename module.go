// Package inspect is an Arandu module that takes an operator into somebody's
// account without signing them out of their own, lets them act there as the
// account's owner, brings them back, and holds the visit to a deadline.
// Everything is recorded in arandu-activitylog under the operator's name.
//
//	module.go   -> registration, routes, handlers, the guard and the migration
//	config.go   -> what the application passes in
//	model.go    -> the inspection
//	policy.go   -> who may go into which account
//	service.go  -> going in, coming back, the deadline, the history
//
// The bar that tells the operator whose account they are in is drawn by the
// application's layout from hesape's view.Inspection, which every page built
// with view.New answers; its button posts to the route named inspect.leave,
// which this module registers.
package inspect

import (
	"context"
	"errors"
	stdhttp "net/http"
	"strconv"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/foundation"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
	"github.com/arandu-io/hesape/database/migrations"
	"github.com/arandu-io/hesape/database/schema"
)

// Module is what the application registers.
type Module struct {
	cfg      Config
	svc      *InspectService
	sessions *security.SessionStore
}

// Compile-time proof that the module honors the contracts it claims.
var (
	_ foundation.Module     = (*Module)(nil)
	_ foundation.Migratable = (*Module)(nil)
)

// New returns the module, or the reason it cannot be built.
func New(cfg Config, db *data.DB, sessions *security.SessionStore) (*Module, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if db == nil {
		return nil, errors.New("inspect: New needs a database handle: the inspections are kept in a table")
	}
	if sessions == nil {
		return nil, errors.New("inspect: New needs the session store: going into an account and back is a change of the session's subject")
	}
	cfg = cfg.withDefaults()
	svc := NewInspectService(db)
	svc.targets, svc.activity, svc.ttl, svc.userType = cfg.Targets, cfg.Activity, cfg.TTL, cfg.UserType
	return &Module{cfg: cfg, svc: svc, sessions: sessions}, nil
}

// Service is the use cases, for an application that calls them from its own
// code. Every method asks the policy.
func (m *Module) Service() *InspectService { return m.svc }

// Name is the module identifier.
func (m *Module) Name() string { return "inspect" }

// Routes registers the module's routes, behind RequireAuth.
//
// inspect.leave is the name hesape's view.New links the way back by, so the
// bar every page draws posts here without the application spelling the path.
func (m *Module) Routes(r *fhttp.Router) {
	r = r.Group("", middleware.RequireAuth(m.sessions))

	r.Action(stdhttp.MethodPost, m.cfg.Prefix+"/users/{id}", m.start).Name("inspect.start")
	r.Action(stdhttp.MethodPost, m.cfg.Prefix+"/leave", m.leave).Name("inspect.leave")
	r.Action(stdhttp.MethodGet, m.cfg.Prefix+"/history", m.history).Name("inspect.history")
}

// start takes the operator into the account named in the path, and lands them
// inside it.
func (m *Module) start(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	acting, record, err := m.svc.Start(ctx.Ctx(), who, ctx.Param("id"))
	if err != nil {
		return err
	}
	if _, err := m.sessions.Rotate(ctx.Ctx(), ctx.Response, m.sessions.IDFromRequest(ctx.Request), acting); err != nil {
		return err
	}
	if ctx.WantsJSON() {
		return ctx.JSON(stdhttp.StatusCreated, inspectionResource{record})
	}
	return ctx.Redirect(m.cfg.Landing)
}

// leave takes the operator back to their own account.
func (m *Module) leave(ctx *fhttp.Context) error {
	who, _ := ctx.User()
	back, record, err := m.svc.Leave(ctx.Ctx(), who, EndLeft)
	if err != nil {
		return err
	}
	if _, err := m.sessions.Rotate(ctx.Ctx(), ctx.Response, m.sessions.IDFromRequest(ctx.Request), back); err != nil {
		return err
	}
	if ctx.WantsJSON() {
		return ctx.JSON(stdhttp.StatusOK, inspectionResource{record})
	}
	return ctx.Redirect(m.cfg.Return)
}

// history answers a page of inspections, for an operator.
func (m *Module) history(ctx *fhttp.Context) error {
	page, _ := strconv.Atoi(ctx.Query("page"))
	who, _ := ctx.User()
	rows, total, err := m.svc.History(ctx.Ctx(), who, HistoryQuery{
		ActorID: ctx.Query("actor"), TargetID: ctx.Query("target"), Status: Status(ctx.Query("status")), Page: page,
	})
	if err != nil {
		return err
	}
	return ctx.JSON(stdhttp.StatusOK, historyResource{rows: rows, total: total})
}

// Guard ends an inspection whose deadline passed: the next request of the
// operator inside the account is taken back to their own, and the end is
// recorded. The application mounts it after RequireAuth on the routes an
// operator can reach from inside an account -- its panel, usually:
//
//	panel := r.Group("/painel", middleware.RequireAuth(sessions), inspectModule.Guard())
func (m *Module) Guard() func(stdhttp.Handler) stdhttp.Handler {
	return func(next stdhttp.Handler) stdhttp.Handler {
		return stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) {
			current, ok := auth.SubjectFrom(r.Context())
			if !ok || current.Impersonator == nil {
				next.ServeHTTP(w, r)
				return
			}
			lapsed, err := m.svc.Lapsed(r.Context(), current)
			if err != nil || !lapsed {
				next.ServeHTTP(w, r)
				return
			}
			back, _, err := m.svc.Leave(r.Context(), current, EndExpired)
			if err != nil {
				stdhttp.Error(w, stdhttp.StatusText(stdhttp.StatusForbidden), stdhttp.StatusForbidden)
				return
			}
			if _, err := m.sessions.Rotate(r.Context(), w, m.sessions.IDFromRequest(r), back); err != nil {
				stdhttp.Error(w, stdhttp.StatusText(stdhttp.StatusInternalServerError), stdhttp.StatusInternalServerError)
				return
			}
			stdhttp.Redirect(w, r, m.cfg.Return, stdhttp.StatusSeeOther)
		})
	}
}

// inspectionResource is one inspection as a response says it.
type inspectionResource struct{ i *Inspection }

func inspectionFields(i *Inspection) map[string]any {
	if i == nil {
		return map[string]any{}
	}
	out := map[string]any{
		"id": i.ID, "actor_id": i.ActorID, "target_id": i.TargetID, "acting": bool(i.Acting),
		"status": string(i.Status), "started_at": i.StartedAt.UTC().Format(time.RFC3339),
		"expires_at": i.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if i.Status == Closed {
		out["closed_at"], out["end_reason"] = i.ClosedAt.UTC().Format(time.RFC3339), i.EndReason
	}
	return out
}

func (r inspectionResource) ToArray() map[string]any { return inspectionFields(r.i) }
func (r inspectionResource) With() map[string]any    { return nil }

type historyResource struct {
	rows  []*Inspection
	total int
}

func (r historyResource) ToArray() map[string]any {
	items := make([]map[string]any, 0, len(r.rows))
	for _, i := range r.rows {
		items = append(items, inspectionFields(i))
	}
	return map[string]any{"items": items, "total": r.total}
}
func (r historyResource) With() map[string]any { return nil }

// Migrations declares the schema this module owns.
func (m *Module) Migrations() []foundation.Migration {
	return []foundation.Migration{createInspections{}}
}

var _ migrations.ReversibleMigration = createInspections{}

// createInspections is the visits operators made to accounts.
type createInspections struct{ migrations.BaseMigration }

// GetName is the migration's identity, and it carries the order.
func (createInspections) GetName() string { return "20261013_0001_create_inspections" }

// Up creates the table.
func (createInspections) Up(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().Create(ctx, inspectionsTable, func(table *schema.Blueprint) {
		table.String("id", maxIdentifierLen).Primary()
		table.String("tenant_id", maxIdentifierLen)
		table.String("actor_id", maxIdentifierLen)
		table.String("target_id", maxIdentifierLen)
		table.UnsignedSmallInteger("acting").Default(0)
		table.String("status", 16)
		table.Timestamp("started_at")
		table.Timestamp("expires_at")
		table.Timestamp("closed_at")
		table.String("end_reason", 16).Default("")
		table.Timestamp("created_at")
		table.Timestamp("updated_at")
		table.Index([]string{"tenant_id", "actor_id", "target_id", "status"}, "inspections_open_idx")
		table.Index([]string{"tenant_id", "started_at", "id"}, "inspections_started_idx")
	})
}

// Down drops the table.
func (createInspections) Down(ctx context.Context, conn migrations.Connection) error {
	return conn.Schema().DropIfExists(ctx, inspectionsTable)
}

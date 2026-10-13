package feature_test

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	hedatabase "github.com/arandu-io/hesape/database"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"
	activitylog "github.com/hyz-is/arandu-activitylog"

	inspect "github.com/hyz-is/arandu-inspect"
)

const (
	appKey = "0123456789abcdef0123456789abcdef"
	tenant = "acme"
	dsn    = "?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(20000)"
)

// people are the accounts the application knows, by identifier.
var people = map[string]security.Subject{
	"op-1":   {ID: "op-1", Tenant: tenant, Roles: []string{inspect.OperatorRole}, Verified: true},
	"op-2":   {ID: "op-2", Tenant: tenant, Roles: []string{inspect.OperatorRole}, Verified: true},
	"ana":    {ID: "ana", Tenant: tenant, Roles: []string{"member"}, Verified: true},
	"bruno":  {ID: "bruno", Tenant: tenant, Verified: true},
	"globex": {ID: "globex", Tenant: "globex", Verified: true},
}

// targets answers the application's accounts.
var targets = inspect.TargetsFunc(func(_ context.Context, _ string, id string) (security.Subject, error) {
	return people[id], nil
})

// world is an application with arandu-activitylog and arandu-inspect over a
// real database, a session store, and a panel route of its own.
type world struct {
	db       *data.DB
	module   *inspect.Module
	sessions *security.SessionStore
	router   *fhttp.Router
	now      *time.Time
}

func install(t *testing.T) *world {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inspect.sqlite")
	handle, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path+dsn)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = handle.Close() })
	connection := hedatabase.NewConnection(handle, path, "", map[string]any{"driver": string(hedatabase.DialectSQLite), "name": "inspect-test"})
	db := data.Wrap(handle, data.DialectSQLite)
	sessions := security.NewSessionStore([]byte(appKey), time.Hour, false, security.NewMemoryBackend())

	activity, err := activitylog.New(activitylog.Config{Tenant: tenant}, db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	module, err := inspect.New(inspect.Config{
		Targets: targets, Activity: activity.Logger(), Landing: "/painel", Return: "/admin/usuarios", TTL: 30 * time.Minute,
	}, db, sessions)
	if err != nil {
		t.Fatal(err)
	}
	migrations := hedatabase.ForMigrations(connection)
	for _, m := range append(activity.Migrations(), module.Migrations()...) {
		if err := m.Up(context.Background(), migrations); err != nil {
			t.Fatalf("applying %s: %v", m.GetName(), err)
		}
	}

	router := fhttp.NewRouter()
	module.Routes(router.ForModule(module.Name()))
	// The application's panel: who the session says is here, and whether
	// they could write.
	panel := router.Group("", middleware.RequireAuth(sessions), module.Guard())
	panel.Action(http.MethodGet, "/painel", func(ctx *fhttp.Context) error {
		who, _ := ctx.User()
		g, err := security.Authorize(ctx.Ctx(), allowAll{}, who, "panel.view", struct{}{})
		if err != nil {
			return err
		}
		by := ""
		if who.Impersonator != nil {
			by = who.Impersonator.ID
		}
		writes := "writes"
		if g.ReadOnly() {
			writes = "reads"
		}
		_, err = ctx.Response.Write([]byte(who.ID + "|" + by + "|" + writes))
		return err
	})
	now := time.Now().UTC()
	w := &world{db: db, module: module, sessions: sessions, router: router, now: &now}
	return w
}

type allowAll struct{}

func (allowAll) Can(context.Context, security.Subject, security.Action, struct{}) error { return nil }

// signIn starts a session for an account and answers its cookies.
func (w *world) signIn(t *testing.T, id string) []*http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	if _, err := w.sessions.Start(context.Background(), rec, people[id]); err != nil {
		t.Fatal(err)
	}
	return rec.Result().Cookies()
}

// do sends a request with the cookies, and answers the response and the
// cookies the browser holds after it.
func (w *world) do(t *testing.T, method, target string, cookies []*http.Cookie) (*httptest.ResponseRecorder, []*http.Cookie) {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	w.router.ServeHTTP(rec, req)
	held := map[string]*http.Cookie{}
	for _, c := range cookies {
		held[c.Name] = c
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(held, c.Name)
		} else {
			held[c.Name] = c
		}
	}
	out := make([]*http.Cookie, 0, len(held))
	for _, c := range held {
		out = append(out, c)
	}
	return rec, out
}

// entries are the activity log's entries of the tenant, oldest first.
func (w *world) entries(t *testing.T) []*activitylog.Activity {
	t.Helper()
	rows, err := activitylog.Activities(w.db).OrderBy("created_at").OrderBy("id").Get(context.Background(), security.SystemGrant(activitylog.ActivityRecord, tenant))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

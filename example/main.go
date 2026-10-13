//go:build example

// Command example wires this package the way an application does, and then
// takes an operator into a user's account and back in one browser: going in
// without signing out, changing something there as the user, coming back, and
// the activity log that recorded all of it under the operator's name.
//
// Run it:
//
//	go run -tags example ./example
//
// It is behind a build tag so that installing this package never compiles it.
// It uses SQLite in a temporary directory and leaves nothing behind, so it needs
// no configuration and no server.
package main

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	"github.com/arandu-io/framework/data"
	fhttp "github.com/arandu-io/framework/http"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	hdatabase "github.com/arandu-io/hesape/database"
	sqliteconnector "github.com/arandu-io/hesape/database/connectors/sqlite"
	activitylog "github.com/hyz-is/arandu-activitylog"

	inspect "github.com/hyz-is/arandu-inspect"
)

// tenant is the customer this example writes as.
const tenant = "acme"

// accounts are the application's users, as each signs in. The package keeps
// none: Targets is how it asks.
var accounts = map[string]security.Subject{
	"op-1": {ID: "op-1", Tenant: tenant, Verified: true, Roles: []string{inspect.OperatorRole}},
	"ana":  {ID: "ana", Tenant: tenant, Verified: true, Roles: []string{"member"}},
}

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "example:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	dir, err := os.MkdirTemp("", "arandu-inspect-example")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	path := filepath.Join(dir, "inspect.db")
	pool, err := sql.Open(sqliteconnector.SQLiteConnector{}.DriverName(), "file:"+path+"?_txlock=immediate")
	if err != nil {
		return err
	}
	defer func() { _ = pool.Close() }()

	// ---- the wiring, which is what an application copies -------------------
	key := []byte("0123456789abcdef0123456789abcdef")
	sessions := security.NewSessionStore(key, time.Hour, false, security.NewMemoryBackend())
	handle := data.Wrap(pool, data.DialectSQLite)
	activity, err := activitylog.New(activitylog.Config{Tenant: tenant}, handle, sessions)
	if err != nil {
		return err
	}
	module, err := inspect.New(inspect.Config{
		Targets: inspect.TargetsFunc(func(_ context.Context, _ string, id string) (security.Subject, error) {
			return accounts[id], nil
		}),
		Activity: activity.Logger(),
		Landing:  "/painel",
		Return:   "/admin/usuarios",
	}, handle, sessions)
	if err != nil {
		return err
	}
	connection := hdatabase.NewConnection(pool, path, "", map[string]any{"driver": string(hdatabase.DialectSQLite), "name": "example"})
	for _, migration := range append(activity.Migrations(), module.Migrations()...) {
		if err := migration.Up(ctx, hdatabase.ForMigrations(connection)); err != nil {
			return fmt.Errorf("applying %s: %w", migration.GetName(), err)
		}
	}

	router := fhttp.NewRouter()
	module.Routes(router.ForModule(module.Name()))
	// The application's panel, behind the guard that ends a lapsed visit. Its
	// settings form writes through the activity log, as an application's
	// screens do.
	panel := router.Group("", middleware.RequireAuth(sessions), module.Guard())
	panel.Action(http.MethodGet, "/painel", func(c *fhttp.Context) error {
		who, _ := c.User()
		by := "themselves"
		if who.Impersonator != nil {
			by = who.Impersonator.ID
		}
		_, err := c.Response.Write([]byte("the panel of " + who.ID + ", used by " + by))
		return err
	})
	panel.Action(http.MethodPost, "/painel/configuracoes", func(c *fhttp.Context) error {
		who, _ := c.User()
		g, err := security.Authorize(c.Ctx(), anybody{}, who, "settings.update", struct{}{})
		if err != nil {
			return err
		}
		if _, err := activity.Logger().Activity(c.Ctx(), g).Event("updated").
			OnRef(activitylog.Ref{Type: "user", ID: who.ID}).WithProperty("field", "nome da empresa").
			Log("alterou o nome da empresa"); err != nil {
			return err
		}
		return c.Redirect("/painel")
	})

	// ---- one browser ------------------------------------------------------
	browser := &browser{router: router}
	rec := httptest.NewRecorder()
	if _, err := sessions.Start(ctx, rec, accounts["op-1"]); err != nil {
		return err
	}
	browser.keep(rec)

	say("in", "the operator posts Inspecionar on ana's row")
	fmt.Printf("  %s\n", browser.send(http.MethodPost, "/inspect/users/ana"))
	fmt.Printf("  %s\n", browser.send(http.MethodGet, "/painel"))

	say("act", "inside, the operator changes a setting as ana would")
	fmt.Printf("  %s\n", browser.send(http.MethodPost, "/painel/configuracoes"))

	say("back", "Voltar ao administrador")
	fmt.Printf("  %s\n", browser.send(http.MethodPost, "/inspect/leave"))
	fmt.Printf("  %s\n", browser.send(http.MethodGet, "/painel"))

	say("log", "what the activity log holds")
	entries, err := activitylog.Activities(handle).OrderBy("created_at").OrderBy("id").Get(ctx, security.SystemGrant(activitylog.ActivityRecord, tenant))
	if err != nil {
		return err
	}
	for _, e := range entries {
		mark := ""
		if m, ok := e.Properties()[activitylog.ImpersonationProperty].(map[string]any); ok {
			mark = fmt.Sprintf(" (inside %v's account, %v)", m["on_behalf_of"], m["mode"])
		}
		fmt.Printf("  %s by %s on %s: %s%s\n", *e.Event, e.Causer().ID, e.Subject().ID, e.Description, mark)
	}
	return nil
}

// anybody is the application's policy for its own settings in this example.
type anybody struct{}

func (anybody) Can(context.Context, security.Subject, security.Action, struct{}) error { return nil }

// browser keeps cookies between requests, as a browser does.
type browser struct {
	router  *fhttp.Router
	cookies map[string]*http.Cookie
}

func (b *browser) keep(rec *httptest.ResponseRecorder) {
	if b.cookies == nil {
		b.cookies = map[string]*http.Cookie{}
	}
	for _, c := range rec.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(b.cookies, c.Name)
		} else {
			b.cookies[c.Name] = c
		}
	}
}

func (b *browser) send(method, target string) string {
	req := httptest.NewRequest(method, target, nil)
	for _, c := range b.cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	b.router.ServeHTTP(rec, req)
	b.keep(rec)
	if loc := rec.Header().Get("Location"); loc != "" {
		return fmt.Sprintf("%s %s -> %d to %s", method, target, rec.Code, loc)
	}
	return fmt.Sprintf("%s %s -> %d: %s", method, target, rec.Code, rec.Body.String())
}

func say(step, what string) { fmt.Printf("\n%s: %s\n", step, what) }

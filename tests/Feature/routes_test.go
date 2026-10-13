package feature_test

import (
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/http/middleware"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/database/migrations"
	activitylog "github.com/hyz-is/arandu-activitylog"

	inspect "github.com/hyz-is/arandu-inspect"
)

func TestAVisitorWithNoSessionIsSentToSignIn(t *testing.T) {
	w := install(t)
	for _, r := range []struct{ method, target string }{
		{http.MethodPost, inspect.DefaultPrefix + "/users/ana"},
		{http.MethodPost, inspect.DefaultPrefix + "/leave"},
		{http.MethodGet, inspect.DefaultPrefix + "/history"},
	} {
		rec, _ := w.do(t, r.method, r.target, nil)
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != middleware.SignInPath {
			t.Errorf("%s %s answered %d to %q", r.method, r.target, rec.Code, rec.Header().Get("Location"))
		}
	}
}

func TestTheModuleRegistersItsRoutesByName(t *testing.T) {
	w := install(t)
	var got []string
	for _, route := range w.router.Routes() {
		if route.Module == "inspect" {
			got = append(got, route.Method+" "+route.Pattern+" "+route.GetName())
		}
	}
	sort.Strings(got)
	want := []string{
		"GET /inspect/history inspect.history",
		"POST /inspect/leave inspect.leave",
		"POST /inspect/users/{id} inspect.start",
	}
	if len(got) != len(want) {
		t.Fatalf("registered %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("registered %v, want %v", got, want)
		}
	}
}

func TestNewRefusesAWiringThatCannotWork(t *testing.T) {
	sessions := security.NewSessionStore([]byte(appKey), time.Hour, false, security.NewMemoryBackend())
	handle := data.Wrap(nil, data.DialectSQLite)
	activity, err := activitylog.New(activitylog.Config{Tenant: tenant}, handle, sessions)
	if err != nil {
		t.Fatal(err)
	}
	valid := inspect.Config{Targets: targets, Activity: activity.Logger()}
	for name, cfg := range map[string]inspect.Config{
		"no targets":           {Activity: activity.Logger()},
		"no activity log":      {Targets: targets},
		"a deadline too long":  {Targets: targets, Activity: activity.Logger(), TTL: inspect.MaxTTL + time.Minute},
		"a landing elsewhere":  {Targets: targets, Activity: activity.Logger(), Landing: "//evil.example"},
		"a prefix that is bad": {Targets: targets, Activity: activity.Logger(), Prefix: "/x{"},
	} {
		if _, err := inspect.New(cfg, handle, sessions); err == nil {
			t.Errorf("a configuration with %s was accepted", name)
		}
	}
	if _, err := inspect.New(valid, nil, sessions); err == nil {
		t.Error("a nil database handle was accepted")
	}
	if _, err := inspect.New(valid, handle, nil); err == nil {
		t.Error("a nil session store was accepted")
	}
	m, err := inspect.New(valid, handle, sessions)
	if err != nil {
		t.Fatalf("a valid wiring was refused: %v", err)
	}
	for _, migration := range m.Migrations() {
		if _, ok := migration.(migrations.ReversibleMigration); !ok {
			t.Errorf("the migration %s has no Down", migration.GetName())
		}
	}
}

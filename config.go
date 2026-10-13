package inspect

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/arandu-io/framework/security"
	activitylog "github.com/hyz-is/arandu-activitylog"
)

const (
	// DefaultPrefix is where the routes are mounted when Config leaves Prefix
	// empty.
	DefaultPrefix = "/inspect"
	// DefaultTTL is how long an inspection lasts before it lapses.
	DefaultTTL = time.Hour
	// MaxTTL is the longest an inspection may be configured to last.
	MaxTTL = 12 * time.Hour
	// DefaultUserType is the kind the activity log names an account by.
	DefaultUserType = "user"
	// LogName is the activity log the package's own entries go in.
	LogName = "inspect"
)

// Targets is the application's answer to "who is this account": the subject
// its owner signs in as -- identifier, tenant, roles, actions -- so the
// operator inside the account is exactly what the owner is. The package keeps
// no users of its own.
type Targets interface {
	Target(ctx context.Context, tenant, userID string) (security.Subject, error)
}

// TargetsFunc is a function that answers Targets.
type TargetsFunc func(ctx context.Context, tenant, userID string) (security.Subject, error)

// Target calls f.
func (f TargetsFunc) Target(ctx context.Context, tenant, userID string) (security.Subject, error) {
	return f(ctx, tenant, userID)
}

// Config is everything the module needs from the application.
type Config struct {
	// Prefix is the path the routes are mounted under. Empty means
	// DefaultPrefix.
	Prefix string

	// Targets loads the account an operator goes into. Required.
	Targets Targets

	// Activity is arandu-activitylog's logger. Required: going in, coming
	// back and the deadline passing are entries, and everything done inside
	// the account is recorded under the operator's name by the log itself.
	Activity *activitylog.Logger

	// Landing is where the operator lands inside the account, and Return
	// where they land back in their own. Empty means "/".
	Landing string
	Return  string

	// TTL is how long an inspection lasts. Zero means DefaultTTL; above
	// MaxTTL is refused.
	TTL time.Duration

	// UserType is the kind the activity log names accounts by, the one the
	// application's own entries use. Empty means DefaultUserType.
	UserType string
}

// Validate reports the first setting that cannot work.
func (c Config) Validate() error {
	for _, p := range []struct{ name, value string }{{"Prefix", c.Prefix}, {"Landing", c.Landing}, {"Return", c.Return}} {
		if p.value != "" && (p.value[0] != '/' || strings.HasPrefix(p.value, "//")) {
			return fmt.Errorf("inspect: Config.%s is %q and has to be a path of this site, starting with a single /", p.name, p.value)
		}
	}
	if c.Prefix != "" {
		if err := validateRoutePrefix(c.Prefix); err != nil {
			return err
		}
	}
	if c.Targets == nil {
		return fmt.Errorf("inspect: Config.Targets is nil: the package keeps no users, and has to ask the application who an account is")
	}
	if c.Activity == nil {
		return fmt.Errorf("inspect: Config.Activity is nil: arandu-inspect needs arandu-activitylog installed and registered in bootstrap/app.go; pass activityModule.Logger() here")
	}
	if c.TTL < 0 || c.TTL > MaxTTL {
		return fmt.Errorf("inspect: Config.TTL is %s, and has to be between 0 and %s, where 0 means %s", c.TTL, MaxTTL, DefaultTTL)
	}
	return nil
}

// validateRoutePrefix registers the routes' shapes on a scratch mux, which
// panics on a pattern the router would refuse too.
func validateRoutePrefix(prefix string) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("inspect: Config.Prefix %q cannot be registered as a route path", prefix)
		}
	}()
	mux := http.NewServeMux()
	mux.Handle(http.MethodPost+" "+prefix+"/users/{id}", http.NotFoundHandler())
	mux.Handle(http.MethodPost+" "+prefix+"/leave", http.NotFoundHandler())
	return nil
}

// withDefaults fills what was left empty.
func (c Config) withDefaults() Config {
	if c.Prefix == "" {
		c.Prefix = DefaultPrefix
	}
	if c.Landing == "" {
		c.Landing = "/"
	}
	if c.Return == "" {
		c.Return = "/"
	}
	if c.TTL == 0 {
		c.TTL = DefaultTTL
	}
	if c.UserType == "" {
		c.UserType = DefaultUserType
	}
	return c
}

package inspect

import (
	"fmt"
	"time"

	"github.com/arandu-io/hesape/database/model"
)

// Inspection is one time an operator went into somebody's account: who, whose
// account, whether they could change it, when it began, when it lapses, and
// how it ended.
//
// It is the package's own record of the visit, kept so the session can be
// held to a deadline and so the list of who went where can be read without
// reading the whole activity log. What the operator did inside the account is
// in the activity log, under their name, and not here.
type Inspection struct {
	model.Model

	ID       string `db:"id"`
	TenantID string `db:"tenant_id"`

	// ActorID is the operator; TargetID the account they went into.
	ActorID  string `db:"actor_id"`
	TargetID string `db:"target_id"`

	// Acting says the operator could change the account, and not only look.
	Acting Flag `db:"acting"`

	// Status is open while the operator is inside, closed once they left or
	// the deadline passed. ClosedAt and EndReason mean something only once it
	// is closed.
	Status    Status    `db:"status"`
	StartedAt time.Time `db:"started_at"`
	ExpiresAt time.Time `db:"expires_at"`
	ClosedAt  time.Time `db:"closed_at"`
	EndReason string    `db:"end_reason"`

	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

// Status is where an inspection stands.
type Status string

const (
	// Open is an operator inside the account now.
	Open Status = "open"
	// Closed is an inspection that ended.
	Closed Status = "closed"
)

// The reasons an inspection ends.
const (
	// EndLeft is the operator going back to their own account.
	EndLeft = "left"
	// EndExpired is the deadline passing.
	EndExpired = "expired"
)

// Expired reports whether the deadline has passed at now.
func (i Inspection) Expired(now time.Time) bool { return !now.Before(i.ExpiresAt) }

var inspectionTable = model.NewTable(model.TableSpec{
	Name:      inspectionsTable,
	New:       func() model.Entity { return new(Inspection) },
	ManualKey: true,
})

// arandu:begin custom

// inspectionsTable is the table name, declared once for the migration and the
// query.
const inspectionsTable = "inspections"

// maxIdentifierLen is the width of an identifier column.
const maxIdentifierLen = 64

// ErrNotFound is a record the caller may not see or that does not exist. It
// wraps model.ErrModelNotFound, which the router answers with 404.
var ErrNotFound = fmt.Errorf("inspect: record not found: %w", model.ErrModelNotFound)

// arandu:end custom

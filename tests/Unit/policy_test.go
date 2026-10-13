package unit_test

import (
	"context"
	"errors"
	"testing"

	"github.com/arandu-io/framework/data"
	"github.com/arandu-io/framework/security"
	"github.com/arandu-io/hesape/auth"
	"github.com/arandu-io/hesape/database/model"

	inspect "github.com/hyz-is/arandu-inspect"
)

// operator is the subject the application gave the inspecting role.
func operator() security.Subject {
	return security.Subject{ID: "op-1", Tenant: "acme", Roles: []string{inspect.OperatorRole}, Verified: true}
}

// member is a signed-in person with no role of this package.
func member() security.Subject {
	return security.Subject{ID: "user-1", Tenant: "acme", Roles: []string{"admin"}, Verified: true}
}

func TestOnlyAnOperatorGoesIntoAccountsAndReadsTheHistory(t *testing.T) {
	t.Parallel()

	for _, action := range []security.Action{inspect.InspectStart, inspect.InspectHistory} {
		if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, operator(), action, inspect.Inspection{}); err != nil {
			t.Errorf("an operator was refused %s: %v", action, err)
		}
		// A role named "admin" is the application's, not this package's.
		if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, member(), action, inspect.Inspection{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a member was allowed %s: %v", action, err)
		}
		if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, security.Guest("acme"), action, inspect.Inspection{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a guest was allowed %s: %v", action, err)
		}
	}
}

func TestNobodyGoesAnywhereFromInsideAnAccount(t *testing.T) {
	t.Parallel()

	inside, err := auth.ImpersonateActing(operator(), member())
	if err != nil {
		t.Fatal(err)
	}
	// Even with the operator's role on the account, which an operator
	// account is refused to begin with.
	inside.Roles = append(inside.Roles, inspect.OperatorRole)
	for _, action := range []security.Action{inspect.InspectStart, inspect.InspectHistory, inspect.InspectLeave} {
		if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, inside, action, inspect.Inspection{}); !errors.Is(err, security.ErrForbidden) {
			t.Errorf("a subject inside an account was allowed %s: %v", action, err)
		}
	}
}

func TestTheOperatorWhoOpenedAnInspectionClosesIt(t *testing.T) {
	t.Parallel()

	opened := inspect.Inspection{ID: "i-1", TenantID: "acme", ActorID: "op-1", TargetID: "user-1"}
	// The operator, back as themselves, without the role any more.
	plain := operator()
	plain.Roles = nil
	if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, plain, inspect.InspectLeave, opened); err != nil {
		t.Fatalf("the operator was refused closing their own inspection: %v", err)
	}
	other := security.Subject{ID: "op-2", Tenant: "acme", Roles: []string{inspect.OperatorRole}, Verified: true}
	if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, other, inspect.InspectLeave, opened); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("another operator closed it: %v", err)
	}
	foreign := opened
	foreign.TenantID = "globex"
	if _, err := security.Authorize(context.Background(), inspect.InspectPolicy{}, operator(), inspect.InspectLeave, foreign); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("an inspection of another tenant was closed: %v", err)
	}
}

// nilHandle is a handle over no database: any statement panics.
func nilHandle() *data.DB { return data.Wrap(nil, data.DialectSQLite) }

func TestTheServiceRefusesBeforeReachingTheModel(t *testing.T) {
	t.Parallel()

	service := inspect.NewInspectService(nil)
	ctx := context.Background()
	if _, _, err := service.Start(ctx, member(), "user-2"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("Start reached the Model before the policy refusal: %v", err)
	}
	if _, _, err := service.History(ctx, member(), inspect.HistoryQuery{}); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("History reached the Model before the policy refusal: %v", err)
	}
	if _, err := service.Find(ctx, member(), "i-1"); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("Find reached the Model before the policy refusal: %v", err)
	}
	if _, err := service.OpenNow(ctx, member()); !errors.Is(err, security.ErrForbidden) {
		t.Fatalf("OpenNow reached the Model before the policy refusal: %v", err)
	}
	if _, _, err := service.Leave(ctx, member(), inspect.EndLeft); !errors.Is(err, inspect.ErrNotInspecting) {
		t.Fatalf("Leave outside an inspection answered %v", err)
	}
	if lapsed, err := service.Lapsed(ctx, member()); err != nil || lapsed {
		t.Fatalf("an ordinary session lapsed: %v, %v", lapsed, err)
	}
}

func TestTheMissingRecordIsTheModelsNotFound(t *testing.T) {
	t.Parallel()

	if !errors.Is(inspect.ErrNotFound, model.ErrModelNotFound) {
		t.Fatal("ErrNotFound does not wrap model.ErrModelNotFound")
	}
}

func TestASystemGrantWithoutATenantReachesNothing(t *testing.T) {
	t.Parallel()

	_, err := inspect.Inspections(nilHandle()).WhereKey("i-1").First(context.Background(), security.SystemGrant(inspect.InspectHistory, ""))
	if !errors.Is(err, model.ErrNoTenant) {
		t.Fatalf("a system grant with no tenant returned %v, want ErrNoTenant", err)
	}
}

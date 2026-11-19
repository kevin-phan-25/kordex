package store

import (
	"strings"
	"testing"
)

func TestSecurityAuditMigrationIsAppendOnlyAndOrdered(t *testing.T) {
	plan, err := migrationPlan()
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) < 10 || plan[9].version != 10 {
		t.Fatalf("migration plan does not include migration 010: %#v", plan)
	}
	sql := string(plan[9].data)
	for _, required := range []string{
		"CREATE TABLE security_audit_events",
		"CREATE TABLE security_audit_chain_head",
		"BEFORE UPDATE OR DELETE ON security_audit_events",
		"BEFORE TRUNCATE ON security_audit_events",
		"REVOKE UPDATE, DELETE, TRUNCATE ON security_audit_events FROM PUBLIC",
	} {
		if !strings.Contains(sql, required) {
			t.Fatalf("migration 010 missing %q", required)
		}
	}
}

func TestValidSecurityDenialRequiresBoundedAuthenticatedAuditFields(t *testing.T) {
	denial := SecurityDenial{
		OrganizationID: NewID(), Actor: "oidc:subject-123", Reason: "role_denied",
		Route: "POST /v1/organizations/{organizationID}/campaigns", Method: "POST",
		Role: "viewer", RequestID: NewID(),
	}
	if !validSecurityDenial(denial) {
		t.Fatal("valid denial rejected")
	}
	for name, mutate := range map[string]func(*SecurityDenial){
		"missing actor":      func(v *SecurityDenial) { v.Actor = "" },
		"invalid target":     func(v *SecurityDenial) { v.OrganizationID = "customer-controlled" },
		"invalid request ID": func(v *SecurityDenial) { v.RequestID = "bad" },
		"unsupported reason": func(v *SecurityDenial) { v.Reason = "arbitrary" },
		"unsupported method": func(v *SecurityDenial) { v.Method = "TRACE" },
		"query in route":     func(v *SecurityDenial) { v.Route += "?token=secret" },
		"newline in route":   func(v *SecurityDenial) { v.Route += "\nforged" },
		"unbounded actor":    func(v *SecurityDenial) { v.Actor = string(make([]byte, 513)) },
		"oversized role":     func(v *SecurityDenial) { v.Role = string(make([]byte, 65)) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := denial
			mutate(&candidate)
			if validSecurityDenial(candidate) {
				t.Fatal("invalid security denial accepted")
			}
		})
	}
}

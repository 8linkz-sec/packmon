package admin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/8linkz-sec/packmon/internal/db"
)

type advisoryCoverageStore struct {
	Store
	page       []db.ManualAdvisory
	pageErr    error
	pageLimit  int
	pageOffset int
	get        *db.ManualAdvisory
	getErr     error
	getID      string
	list       []db.ManualAdvisory
	listErr    error
	listLimit  int
}

func (s *advisoryCoverageStore) ListManualAdvisoriesPage(_ context.Context, limit, offset int) ([]db.ManualAdvisory, error) {
	s.pageLimit = limit
	s.pageOffset = offset
	return append([]db.ManualAdvisory(nil), s.page...), s.pageErr
}

func (s *advisoryCoverageStore) GetManualAdvisory(_ context.Context, id string) (*db.ManualAdvisory, error) {
	s.getID = id
	if s.get == nil {
		return nil, s.getErr
	}
	copyValue := *s.get
	return &copyValue, s.getErr
}

func (s *advisoryCoverageStore) ListManualAdvisories(_ context.Context, limit int) ([]db.ManualAdvisory, error) {
	s.listLimit = limit
	return append([]db.ManualAdvisory(nil), s.list...), s.listErr
}

func manualAdvisoryFixture(id string) db.ManualAdvisory {
	return db.ManualAdvisory{
		ID:          id,
		FindingType: "vulnerability",
		Ecosystem:   "npm",
		Name:        "fixture-package",
		Severity:    "HIGH",
		Summary:     "fixture summary",
		UpdatedAt:   time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
}

func TestAdminAdvisoriesUsesOptionalPagingAndEditLookup(t *testing.T) {
	base := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, base, adminFlowConfig())
	edit := manualAdvisoryFixture("manual:outside-page")
	store := &advisoryCoverageStore{
		Store: handler.store,
		page:  []db.ManualAdvisory{manualAdvisoryFixture("manual:on-page")},
		get:   &edit,
	}
	handler.store = store

	req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?offset=200&edit=manual:outside-page")
	rec := httptest.NewRecorder()
	handler.HandleAdminAdvisories(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if store.pageLimit != adminManualAdvisoryPageSize+1 || store.pageOffset != 200 {
		t.Fatalf("page call = limit %d offset %d, want 101/200", store.pageLimit, store.pageOffset)
	}
	if store.getID != edit.ID {
		t.Fatalf("edit lookup ID = %q, want %q", store.getID, edit.ID)
	}
	body := rec.Body.String()
	for _, want := range []string{"manual:on-page", edit.ID, `value="fixture-package"`, `value="2026-01-02T03:04:05Z"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q", want)
		}
	}
}

func TestManualAdvisoryOptionalStoreOutcomes(t *testing.T) {
	t.Run("pager", func(t *testing.T) {
		items := make([]db.ManualAdvisory, adminManualAdvisoryPageSize+1)
		for i := range items {
			items[i] = manualAdvisoryFixture(fmt.Sprintf("manual:%03d", i))
		}
		store := &advisoryCoverageStore{page: items}
		h := &AdminHandler{store: store}
		got, hasNext, err := h.listManualAdvisoryPage(context.Background(), 7)
		if err != nil || !hasNext || len(got) != adminManualAdvisoryPageSize {
			t.Fatalf("paged result = %d, %v, %v", len(got), hasNext, err)
		}
		store.pageErr = errors.New("page failed")
		if _, _, err := h.listManualAdvisoryPage(context.Background(), 0); err == nil {
			t.Fatal("page error = nil")
		}
	})

	t.Run("fallback", func(t *testing.T) {
		items := []db.ManualAdvisory{
			manualAdvisoryFixture("manual:0"),
			manualAdvisoryFixture("manual:1"),
			manualAdvisoryFixture("manual:2"),
		}
		store := &advisoryCoverageStore{list: items}
		h := &AdminHandler{store: struct{ Store }{Store: store}}
		got, hasNext, err := h.listManualAdvisoryPage(context.Background(), 2)
		if err != nil || hasNext || len(got) != 1 || got[0].ID != "manual:2" || store.listLimit != 103 {
			t.Fatalf("fallback result = %+v, %v, %v limit=%d", got, hasNext, err, store.listLimit)
		}
		got, hasNext, err = h.listManualAdvisoryPage(context.Background(), 20)
		if err != nil || hasNext || len(got) != 0 {
			t.Fatalf("out-of-range result = %+v, %v, %v", got, hasNext, err)
		}
		store.listErr = errors.New("list failed")
		if _, _, err := h.listManualAdvisoryPage(context.Background(), 0); err == nil {
			t.Fatal("fallback list error = nil")
		}
	})

	t.Run("getter", func(t *testing.T) {
		item := manualAdvisoryFixture("manual:wanted")
		store := &advisoryCoverageStore{get: &item}
		h := &AdminHandler{store: store}
		if got, found, err := h.findManualAdvisoryByID(context.Background(), "  manual:wanted  "); err != nil || !found || got.ID != item.ID {
			t.Fatalf("getter result = %+v, %v, %v", got, found, err)
		}
		store.get = nil
		if _, found, err := h.findManualAdvisoryByID(context.Background(), "manual:missing"); err != nil || found {
			t.Fatalf("missing getter = %v, %v", found, err)
		}
		store.getErr = errors.New("get failed")
		if _, _, err := h.findManualAdvisoryByID(context.Background(), "manual:error"); err == nil {
			t.Fatal("getter error = nil")
		}
		if _, found, err := h.findManualAdvisoryByID(context.Background(), " "); err != nil || found {
			t.Fatalf("blank ID = %v, %v", found, err)
		}
	})

	t.Run("fallback lookup", func(t *testing.T) {
		item := manualAdvisoryFixture("manual:wanted")
		store := &advisoryCoverageStore{list: []db.ManualAdvisory{item}}
		h := &AdminHandler{store: struct{ Store }{Store: store}}
		if got, found, err := h.findManualAdvisoryByID(context.Background(), item.ID); err != nil || !found || got.ID != item.ID || store.listLimit != 500 {
			t.Fatalf("fallback lookup = %+v, %v, %v limit=%d", got, found, err, store.listLimit)
		}
		if _, found, err := h.findManualAdvisoryByID(context.Background(), "manual:missing"); err != nil || found {
			t.Fatalf("fallback missing = %v, %v", found, err)
		}
		store.listErr = errors.New("list failed")
		if _, _, err := h.findManualAdvisoryByID(context.Background(), item.ID); err == nil {
			t.Fatal("fallback lookup error = nil")
		}
	})
}

func TestAdminAdvisoryRevisionValidationPreservesFormState(t *testing.T) {
	store := newAdminStoreStub()
	existing := manualAdvisoryFixture("manual:revision")
	store.manual[existing.ID] = existing
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())

	post := func(values url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", values)
		rec := httptest.NewRecorder()
		handler.HandleAdvisoryCreate(rec, req)
		return rec
	}

	rec := post(url.Values{
		"id":           {existing.ID},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"preserved-name"},
		"severity":     {"HIGH"},
		"summary":      {"preserved summary"},
		"updated_at":   {"not-a-revision"},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "preserved-name") || !strings.Contains(rec.Body.String(), "Invalid advisory revision") {
		t.Fatalf("malformed revision response = %d %q", rec.Code, rec.Body.String())
	}

	revision := existing.UpdatedAt.Format(time.RFC3339Nano)
	rec = post(url.Values{
		"id":           {existing.ID},
		"finding_type": {"vulnerability"},
		"ecosystem":    {"npm"},
		"name":         {"still-preserved"},
		"severity":     {"INVALID"},
		"summary":      {"preserved again"},
		"updated_at":   {revision},
	})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "still-preserved") || !strings.Contains(body, revision) || !strings.Contains(body, "INVALID") {
		t.Fatalf("validated revision response = %d %q", rec.Code, body)
	}
	if got := store.manual[existing.ID]; got.Name != existing.Name || !got.UpdatedAt.Equal(existing.UpdatedAt) {
		t.Fatalf("stored advisory mutated = %+v", got)
	}
	if len(store.audit) != 0 {
		t.Fatalf("audit entries = %d, want 0", len(store.audit))
	}

	req, sess := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
	rec = httptest.NewRecorder()
	handler.renderManualAdvisoryValidationError(rec, req, sess, manualAdvisoryInput{Name: "default-message"}, false, manualAdvisoryValidationError{
		FieldErrors: map[string]string{"name": "invalid"},
	})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "Manual advisory could not be saved") {
		t.Fatalf("default validation response = %d %q", rec.Code, rec.Body.String())
	}
}

func TestManualAdvisoryValidationBoundariesAndDefaults(t *testing.T) {
	valid := manualAdvisoryInput{
		ID:          "manual:boundary",
		FindingType: "malicious",
		Ecosystem:   "npm",
		Name:        strings.Repeat("n", ManualAdvisoryNameMaxLength),
		Severity:    "HIGH",
		Summary:     strings.Repeat("s", ManualAdvisorySummaryMaxLength),
		Description: strings.Repeat("d", ManualAdvisoryDescriptionMaxLength),
	}
	got, validation, err := validateManualAdvisoryInput(valid)
	if err != nil || validation.HasErrors() || got.RiskType != "other" {
		t.Fatalf("max boundary validation = %+v, %+v, %v", got, validation, err)
	}

	cases := []struct {
		name  string
		input manualAdvisoryInput
		field string
	}{
		{name: "missing ecosystem", input: func() manualAdvisoryInput { v := valid; v.Ecosystem = ""; return v }(), field: "ecosystem"},
		{name: "name too long", input: func() manualAdvisoryInput { v := valid; v.Name += "n"; return v }(), field: "name"},
		{name: "summary too long", input: func() manualAdvisoryInput { v := valid; v.Summary += "s"; return v }(), field: "summary"},
		{name: "description too long", input: func() manualAdvisoryInput { v := valid; v.Description += "d"; return v }(), field: "description"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			_, validation, err := validateManualAdvisoryInput(tt.input)
			if err != nil || validation.FieldErrors[tt.field] == "" {
				t.Fatalf("validation = %+v, %v", validation, err)
			}
		})
	}

	store := newAdminStoreStub()
	handler, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
	req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
		"id":           {valid.ID},
		"finding_type": {valid.FindingType},
		"ecosystem":    {valid.Ecosystem},
		"name":         {valid.Name},
		"severity":     {valid.Severity},
		"summary":      {valid.Summary},
		"description":  {valid.Description},
	})
	rec := httptest.NewRecorder()
	handler.HandleAdvisoryCreate(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("persist status = %d, want 303", rec.Code)
	}
	stored := store.manual[valid.ID]
	if stored.RiskType != "other" || stored.Name != valid.Name || stored.Summary != valid.Summary || stored.Description != valid.Description {
		t.Fatalf("stored advisory = %+v", stored)
	}
	if len(store.audit) != 1 || store.audit[0].Action != "advisory_create" {
		t.Fatalf("audit = %+v", store.audit)
	}
}

func TestAdminAdvisoryFailuresDoNotClaimMutationOrAudit(t *testing.T) {
	assertNoSuccess := func(t *testing.T, rec *httptest.ResponseRecorder) {
		t.Helper()
		if strings.Contains(rec.Header().Get("Location"), "msg=") || strings.Contains(rec.Body.String(), "Advisory created") || strings.Contains(rec.Body.String(), "Advisory updated") || strings.Contains(rec.Body.String(), "Advisory deleted") {
			t.Fatalf("failure claimed success: location=%q body=%q", rec.Header().Get("Location"), rec.Body.String())
		}
	}

	t.Run("unauthenticated page", func(t *testing.T) {
		store := newAdminStoreStub()
		h, _, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		rec := httptest.NewRecorder()
		h.HandleAdminAdvisories(rec, httptest.NewRequest(http.MethodGet, "/admin/advisories", nil))
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/login?next=%2Fadmin%2Fadvisories" {
			t.Fatalf("unauthenticated response = %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if len(store.audit) != 0 || len(store.manual) != 0 {
			t.Fatalf("unauthenticated read changed state: manual=%d audit=%d", len(store.manual), len(store.audit))
		}
	})

	t.Run("delete confirmation mismatch", func(t *testing.T) {
		store := newAdminStoreStub()
		fixture := manualAdvisoryFixture("manual:confirmation")
		store.manual[fixture.ID] = fixture
		h, sm, _ := newAdminFlowHandler(t, store, adminFlowConfig())
		req, _ := authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{"id": {fixture.ID}, "confirm_id": {"manual:other"}})
		rec := httptest.NewRecorder()
		h.HandleAdvisoryDelete(rec, req)
		if rec.Code != http.StatusSeeOther || !strings.Contains(rec.Header().Get("Location"), "Confirm+advisory+ID") {
			t.Fatalf("confirmation response = %d %q", rec.Code, rec.Header().Get("Location"))
		}
		if _, ok := store.manual[fixture.ID]; !ok || len(store.audit) != 0 {
			t.Fatalf("confirmation failure changed state: stored=%v audit=%d", ok, len(store.audit))
		}
	})

	t.Run("page and getter", func(t *testing.T) {
		base := newAdminStoreStub()
		h, sm, _ := newAdminFlowHandler(t, base, adminFlowConfig())
		store := &advisoryCoverageStore{Store: h.store, pageErr: errors.New("page down")}
		h.store = store
		req, _ := authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories")
		rec := httptest.NewRecorder()
		h.HandleAdminAdvisories(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Manual advisories could not be loaded") {
			t.Fatalf("page failure = %d %q", rec.Code, rec.Body.String())
		}

		store.pageErr = nil
		store.getErr = errors.New("getter down")
		req, _ = authenticatedAdminRequest(t, sm, http.MethodGet, "/admin/advisories?edit=manual:missing")
		rec = httptest.NewRecorder()
		h.HandleAdminAdvisories(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Manual advisories could not be loaded") {
			t.Fatalf("getter failure = %d %q", rec.Code, rec.Body.String())
		}
		if len(base.audit) != 0 || len(base.manual) != 0 {
			t.Fatalf("read failure changed state: manual=%d audit=%d", len(base.manual), len(base.audit))
		}
	})

	for _, tt := range []struct {
		name       string
		fail       map[string]error
		seed       bool
		delete     bool
		wantStored bool
	}{
		{name: "lookup", fail: map[string]error{"ListManualAdvisories": errors.New("lookup down")}},
		{name: "create", fail: map[string]error{"UpsertManualAdvisory": errors.New("create down")}},
		{name: "create audit", fail: map[string]error{"InsertAdminAuditLog": errors.New("audit down")}},
		{name: "update", fail: map[string]error{"UpsertManualAdvisory": errors.New("update down")}, seed: true, wantStored: true},
		{name: "delete lookup", fail: map[string]error{"ListManualAdvisories": errors.New("lookup down")}, seed: true, delete: true, wantStored: true},
		{name: "delete", fail: map[string]error{"DeleteManualAdvisory": errors.New("delete down")}, seed: true, delete: true, wantStored: true},
		{name: "delete audit", fail: map[string]error{"InsertAdminAuditLog": errors.New("audit down")}, seed: true, delete: true, wantStored: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			store := newAdminErrorStore()
			for key, err := range tt.fail {
				store.fail[key] = err
			}
			fixture := manualAdvisoryFixture("manual:failure")
			if tt.seed {
				store.manual[fixture.ID] = fixture
			}
			h, sm := newAdminHandlerForStore(t, store, adminFlowConfig())
			var req *http.Request
			if tt.delete {
				req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/delete", url.Values{"id": {fixture.ID}, "confirm_id": {fixture.ID}})
			} else {
				req, _ = authenticatedAdminFormRequest(t, sm, "/admin/advisories/create", url.Values{
					"id": {fixture.ID}, "finding_type": {"vulnerability"}, "ecosystem": {"npm"}, "name": {"changed"}, "severity": {"HIGH"}, "summary": {"changed"}, "updated_at": {fixture.UpdatedAt.Format(time.RFC3339Nano)},
				})
			}
			rec := httptest.NewRecorder()
			if tt.delete {
				h.HandleAdvisoryDelete(rec, req)
			} else {
				h.HandleAdvisoryCreate(rec, req)
			}
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("status = %d, want 303", rec.Code)
			}
			assertNoSuccess(t, rec)
			_, stored := store.manual[fixture.ID]
			if stored != tt.wantStored {
				t.Fatalf("stored = %v, want %v", stored, tt.wantStored)
			}
			if len(store.audit) != 0 {
				t.Fatalf("audit = %+v, want none", store.audit)
			}
		})
	}
}

func TestManualAdvisoryGenerationAndZeroValueHelpers(t *testing.T) {
	id, err := generateManualAdvisoryID()
	if err != nil {
		t.Fatalf("generateManualAdvisoryID() error = %v", err)
	}
	pattern := regexp.MustCompile(`^manual:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	if !pattern.MatchString(id) {
		t.Fatalf("generated ID = %q, want UUID v4 with RFC 4122 variant", id)
	}

	input, validation, err := validateManualAdvisoryInput(manualAdvisoryInput{
		Ecosystem: "npm", Name: "generated", Severity: "LOW", Summary: "generated ID",
	})
	if err != nil || validation.HasErrors() || !pattern.MatchString(input.ID) || input.FindingType != "vulnerability" {
		t.Fatalf("generated validation = %+v, %+v, %v", input, validation, err)
	}

	if view := manualAdvisoryToView(db.ManualAdvisory{}); view.UpdatedAt != "" {
		t.Fatalf("zero advisory view revision = %q", view.UpdatedAt)
	}
	if view := manualAdvisoryInputToView(manualAdvisoryInput{}); view.UpdatedAt != "" {
		t.Fatalf("zero input view revision = %q", view.UpdatedAt)
	}
	if invalidManualAdvisoryFindingType(nil) != "" || invalidManualAdvisoryEcosystem(nil) != "" || invalidManualAdvisorySeverity(nil) != "" {
		t.Fatal("nil validation helpers returned non-empty values")
	}
	if got := advisoryReturnOffset(nil); got != 0 {
		t.Fatalf("nil return offset = %d", got)
	}
	if got := adminAdvisoryURL(0, nil); got != "/admin/advisories" {
		t.Fatalf("empty advisory URL = %q", got)
	}
	if got, ok := normalizeAdvisoryFindingType("unknown"); ok || got != "" {
		t.Fatalf("unknown finding type = %q, %v", got, ok)
	}
	if _, found, err := (&AdminHandler{}).loadExistingManualAdvisory(context.Background(), ""); err != nil || found {
		t.Fatalf("blank load = %v, %v", found, err)
	}

	var validationError manualAdvisoryValidationError
	validationError.setMessage("first")
	validationError.setMessage("second")
	validationError.addField("name", "required")
	if validationError.Message != "first" || validationError.FieldErrors["name"] != "required" || !validationError.HasErrors() {
		t.Fatalf("validation helper state = %+v", validationError)
	}
}

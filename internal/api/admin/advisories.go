package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/8linkz-sec/packmon/internal/auth"
	"github.com/8linkz-sec/packmon/internal/db"
	"github.com/8linkz-sec/packmon/internal/domain"
	"github.com/8linkz-sec/packmon/internal/web"
)

const (
	// ManualAdvisoryNameMaxLength is shared by admin validation and the
	// rendered advisory form maxlength for package names.
	ManualAdvisoryNameMaxLength = 256
	// ManualAdvisorySummaryMaxLength is shared by admin validation and the
	// rendered advisory form maxlength for summaries.
	ManualAdvisorySummaryMaxLength = 1000
	// ManualAdvisoryDescriptionMaxLength is shared by admin validation and the
	// rendered advisory form maxlength for descriptions.
	ManualAdvisoryDescriptionMaxLength = 8000
	adminManualAdvisoryPageSize        = 100
)

type manualAdvisoryGetter interface {
	GetManualAdvisory(ctx context.Context, id string) (*db.ManualAdvisory, error)
}

type manualAdvisoryPageLister interface {
	ListManualAdvisoriesPage(ctx context.Context, limit, offset int) ([]db.ManualAdvisory, error)
}

type manualAdvisoryView struct {
	ID          string
	FindingType string
	Ecosystem   string
	Name        string
	Severity    string
	RiskType    string
	Summary     string
	Description string
	UpdatedAt   string
}

type manualAdvisoryInput struct {
	ID                string
	FindingType       string
	Ecosystem         string
	Name              string
	RiskType          string
	Severity          string
	Summary           string
	Description       string
	ExpectedUpdatedAt time.Time
}

type manualAdvisoryPageOptions struct {
	Offset        int
	EditID        string
	Message       string
	Error         string
	FormAdvisory  *manualAdvisoryView
	FormIsEditing bool
	FieldErrors   map[string]string
	Status        int
}

type manualAdvisoryValidationError struct {
	Message     string
	FieldErrors map[string]string
}

func (e manualAdvisoryValidationError) HasErrors() bool {
	return e.Message != "" || len(e.FieldErrors) > 0
}

func (e *manualAdvisoryValidationError) addField(field, message string) {
	if e.FieldErrors == nil {
		e.FieldErrors = make(map[string]string)
	}
	e.FieldErrors[field] = message
}

func (e *manualAdvisoryValidationError) setMessage(message string) {
	if e.Message == "" {
		e.Message = message
	}
}

// HandleAdminAdvisories serves GET /admin/advisories with the manual advisory form.
func (h *AdminHandler) HandleAdminAdvisories(w http.ResponseWriter, r *http.Request) {
	sess := h.requireAdmin(w, r)
	if sess == nil {
		return
	}

	h.renderAdminAdvisoriesPage(w, r, sess, manualAdvisoryPageOptions{
		Offset:  parseNonNegativeOffset(r.URL.Query().Get("offset")),
		EditID:  r.URL.Query().Get("edit"),
		Message: r.URL.Query().Get("msg"),
		Error:   r.URL.Query().Get("err"),
	})
}

func (h *AdminHandler) renderAdminAdvisoriesPage(w http.ResponseWriter, r *http.Request, sess *auth.Session, opts manualAdvisoryPageOptions) {
	csrfToken, ok := h.adminCSRFToken(w, r, sess, "admin advisories")
	if !ok {
		return
	}
	offset := opts.Offset
	advisories, hasNext, err := h.listManualAdvisoryPage(r.Context(), offset)
	advisoriesLoadError := ""
	if err != nil {
		h.logger.Error("admin advisories: failed to list advisories", h.adminLogAttrs(r, "error", err)...)
		advisoriesLoadError = web.Message("admin.advisories.error.load")
	}

	views := make([]manualAdvisoryView, 0, len(advisories))
	var editAdvisory *manualAdvisoryView
	editID := opts.EditID
	for _, advisory := range advisories {
		view := manualAdvisoryToView(advisory)
		views = append(views, view)
		if editID != "" && advisory.ID == editID {
			copyValue := view
			editAdvisory = &copyValue
		}
	}
	if editID != "" && editAdvisory == nil && advisoriesLoadError == "" {
		advisory, found, err := h.findManualAdvisoryByID(r.Context(), editID)
		if err != nil {
			h.logger.Error("admin advisories: failed to load edit advisory", h.adminLogAttrs(r, "error", err, "id", editID)...)
			advisoriesLoadError = web.Message("admin.advisories.error.load")
		} else if found {
			view := manualAdvisoryToView(advisory)
			editAdvisory = &view
		}
	}

	formAdvisory := editAdvisory
	isEditing := editAdvisory != nil
	if opts.FormAdvisory != nil {
		formAdvisory = opts.FormAdvisory
		isEditing = opts.FormIsEditing
	}

	newAdvisoryID := ""
	pageError := opts.Error
	if editID != "" && editAdvisory == nil && advisoriesLoadError == "" && pageError == "" {
		pageError = web.Message("admin.advisories.error.not_found")
	}
	if formAdvisory == nil {
		generatedID, err := generateManualAdvisoryID()
		if err != nil {
			h.logger.Error("admin advisories: failed to generate create advisory ID", h.adminLogAttrs(r, "error", err)...)
			if pageError == "" {
				pageError = web.Message("admin.advisories.error.prepare_form")
			}
		} else {
			newAdvisoryID = generatedID
		}
	}

	data := map[string]any{
		"ActiveNav":                          "admin",
		"CSRFToken":                          csrfToken,
		"Message":                            opts.Message,
		"Error":                              pageError,
		"Advisories":                         views,
		"AdvisoriesLoadError":                advisoriesLoadError,
		"AdvisoryPageOutOfRange":             advisoriesLoadError == "" && offset > 0 && len(views) == 0,
		"EditAdvisory":                       formAdvisory,
		"NewAdvisoryID":                      newAdvisoryID,
		"IsEditing":                          isEditing,
		"ShowRiskTypeControl":                true,
		"ManualAdvisoryNameMaxLength":        ManualAdvisoryNameMaxLength,
		"ManualAdvisorySummaryMaxLength":     ManualAdvisorySummaryMaxLength,
		"ManualAdvisoryDescriptionMaxLength": ManualAdvisoryDescriptionMaxLength,
		"AdvisoryHasPrevious":                offset > 0,
		"AdvisoryHasNext":                    hasNext,
		"AdvisoryCurrentOffset":              offset,
		"AdvisoryPreviousOffset":             max(offset-adminManualAdvisoryPageSize, 0),
		"AdvisoryNextOffset":                 offset + adminManualAdvisoryPageSize,
		"AdvisoryPageStart":                  auditPageStart(offset, len(views)),
		"AdvisoryPageEnd":                    offset + len(views),
		"AdvisoryFieldErrors":                opts.FieldErrors,
		"InvalidAdvisoryFindingType":         invalidManualAdvisoryFindingType(formAdvisory),
		"InvalidAdvisoryEcosystem":           invalidManualAdvisoryEcosystem(formAdvisory),
		"InvalidAdvisorySeverity":            invalidManualAdvisorySeverity(formAdvisory),
	}
	addAdminBootstrapPageState(data, h.adminBootstrapPageState(r.Context(), r, sess, "admin advisories"))
	h.renderAdminWithStatus(w, "admin/advisories.html", data, opts.Status)
}

// HandleAdvisoryCreate handles POST /admin/advisories/create.
func (h *AdminHandler) HandleAdvisoryCreate(w http.ResponseWriter, r *http.Request) {
	sess, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "advisory_create",
		bootstrapRedirectPath: "/admin/advisories",
	})
	if !ok {
		return
	}

	input, formValidation := parseManualAdvisoryForm(r)
	previous, isEditing, err := h.loadExistingManualAdvisory(r.Context(), input.ID)
	if err != nil {
		h.logger.Error("admin advisories: failed to load advisory before save", h.adminLogAttrs(r, "error", err, "id", input.ID)...)
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.load_existing"))
		return
	}
	if formValidation.HasErrors() {
		h.renderManualAdvisoryValidationError(w, r, sess, input, isEditing, formValidation)
		return
	}

	input, validationErr, err := validateManualAdvisoryInput(input)
	if err != nil {
		h.logger.Error("admin advisories: failed to generate advisory ID", h.adminLogAttrs(r, "error", err)...)
	}
	if validationErr.HasErrors() {
		h.renderManualAdvisoryValidationError(w, r, sess, input, isEditing, validationErr)
		return
	}

	advisory := buildManualAdvisoryRecord(input)
	h.saveManualAdvisoryAndRedirect(w, r, advisory, previous, isEditing)
}

func parseManualAdvisoryForm(r *http.Request) (manualAdvisoryInput, manualAdvisoryValidationError) {
	input := manualAdvisoryInput{
		ID:          strings.TrimSpace(r.PostForm.Get("id")),
		FindingType: strings.ToLower(strings.TrimSpace(r.PostForm.Get("finding_type"))),
		Ecosystem:   strings.ToLower(strings.TrimSpace(r.PostForm.Get("ecosystem"))),
		Name:        strings.TrimSpace(r.PostForm.Get("name")),
		RiskType:    strings.TrimSpace(r.PostForm.Get("risk_type")),
		Severity:    strings.ToUpper(strings.TrimSpace(r.PostForm.Get("severity"))),
		Summary:     strings.TrimSpace(r.PostForm.Get("summary")),
		Description: r.PostForm.Get("description"),
	}
	if raw := strings.TrimSpace(r.PostForm.Get("updated_at")); raw != "" {
		parsed, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			return input, manualAdvisoryValidationError{Message: web.Message("admin.advisories.error.invalid_revision")}
		}
		input.ExpectedUpdatedAt = parsed.UTC()
	}
	return input, manualAdvisoryValidationError{}
}

func (h *AdminHandler) loadExistingManualAdvisory(ctx context.Context, advisoryID string) (db.ManualAdvisory, bool, error) {
	if advisoryID == "" {
		return db.ManualAdvisory{}, false, nil
	}
	return h.findManualAdvisoryByID(ctx, advisoryID)
}

func validateManualAdvisoryInput(input manualAdvisoryInput) (manualAdvisoryInput, manualAdvisoryValidationError, error) {
	var validation manualAdvisoryValidationError
	if input.FindingType == "" {
		input.FindingType = "vulnerability"
	} else if findingType, ok := normalizeAdvisoryFindingType(input.FindingType); ok {
		input.FindingType = findingType
	} else {
		validation.addField("finding_type", web.Message("admin.advisories.field.finding_type"))
		validation.setMessage(web.Message("admin.advisories.error.invalid_finding_type"))
	}
	if input.Ecosystem == "" {
		validation.addField("ecosystem", web.Message("admin.advisories.field.ecosystem_required"))
		validation.setMessage(web.Message("admin.advisories.error.required_fields"))
	}
	if input.Name == "" {
		validation.addField("name", web.Message("admin.advisories.field.name_required"))
		validation.setMessage(web.Message("admin.advisories.error.required_fields"))
	}
	if input.Severity == "" {
		validation.addField("severity", web.Message("admin.advisories.field.severity_required"))
		validation.setMessage(web.Message("admin.advisories.error.required_fields"))
	}
	if input.Summary == "" {
		validation.addField("summary", web.Message("admin.advisories.field.summary_required"))
		validation.setMessage(web.Message("admin.advisories.error.required_fields"))
	}

	// The HTML <select> only constrains the browser; a direct request can
	// submit arbitrary values. Validate against the supported sets so a
	// mistyped severity cannot silently rank 0 (and never block) and a bogus
	// ecosystem cannot create findings that never match a real scan.
	if input.Severity != "" {
		switch input.Severity {
		case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		default:
			validation.addField("severity", web.Message("admin.advisories.field.severity_required"))
			validation.setMessage(web.Message("admin.advisories.error.invalid_severity"))
		}
	}
	if input.Ecosystem != "" {
		ecosystem := domain.Ecosystem(input.Ecosystem)
		if !ecosystem.Valid() {
			validation.addField("ecosystem", web.Message("admin.advisories.field.ecosystem_required"))
			validation.setMessage(web.Message("admin.advisories.error.unknown_ecosystem"))
		} else if ecosystem.InventoryOnly() {
			validation.addField("ecosystem", web.Message("admin.advisories.error.inventory_only_unsupported")+".")
			validation.setMessage(web.Message("admin.advisories.error.inventory_only_unsupported"))
		}
	}
	if len(input.Name) > ManualAdvisoryNameMaxLength {
		validation.addField("name", web.Message("admin.advisories.field.max_length", ManualAdvisoryNameMaxLength))
		validation.setMessage(web.Message("admin.advisories.error.max_length"))
	}
	if len(input.Summary) > ManualAdvisorySummaryMaxLength {
		validation.addField("summary", web.Message("admin.advisories.field.max_length", ManualAdvisorySummaryMaxLength))
		validation.setMessage(web.Message("admin.advisories.error.max_length"))
	}
	if len(input.Description) > ManualAdvisoryDescriptionMaxLength {
		validation.addField("description", web.Message("admin.advisories.field.max_length", ManualAdvisoryDescriptionMaxLength))
		validation.setMessage(web.Message("admin.advisories.error.max_length"))
	}
	if validation.HasErrors() {
		return input, validation, nil
	}

	if input.ID == "" {
		advisoryID, err := generateManualAdvisoryID()
		if err != nil {
			return input, manualAdvisoryValidationError{Message: web.Message("admin.advisories.error.generate_id")}, err
		}
		input.ID = advisoryID
	} else if !strings.HasPrefix(input.ID, domain.ManualAdvisoryIDPrefix) {
		// Operator-supplied IDs must stay within the manual: namespace so they
		// cannot collide with and overwrite a feed-sourced advisory (e.g. a
		// CVE/GHSA ID) via ON CONFLICT (id) DO UPDATE.
		return input, manualAdvisoryValidationError{Message: web.Message("admin.advisories.error.id_prefix")}, nil
	}
	switch input.FindingType {
	case "malicious":
		if strings.TrimSpace(input.RiskType) == "" {
			input.RiskType = "other"
		}
	case "vulnerability":
		input.RiskType = ""
	}
	return input, manualAdvisoryValidationError{}, nil
}

func (h *AdminHandler) renderManualAdvisoryValidationError(w http.ResponseWriter, r *http.Request, sess *auth.Session, input manualAdvisoryInput, isEditing bool, validation manualAdvisoryValidationError) {
	if validation.Message == "" {
		validation.Message = web.Message("admin.advisories.error.save_default")
	}
	view := manualAdvisoryInputToView(input)
	h.renderAdminAdvisoriesPage(w, r, sess, manualAdvisoryPageOptions{
		Offset:        advisoryReturnOffset(r),
		Error:         validation.Message,
		FormAdvisory:  &view,
		FormIsEditing: isEditing,
		FieldErrors:   validation.FieldErrors,
		Status:        http.StatusBadRequest,
	})
}

func buildManualAdvisoryRecord(input manualAdvisoryInput) *db.ManualAdvisory {
	return &db.ManualAdvisory{
		ID:          input.ID,
		FindingType: input.FindingType,
		Ecosystem:   input.Ecosystem,
		Name:        input.Name,
		RiskType:    input.RiskType,
		Severity:    input.Severity,
		Summary:     input.Summary,
		Description: input.Description,
		UpdatedAt:   input.ExpectedUpdatedAt,
	}
}

func (h *AdminHandler) saveManualAdvisoryAndRedirect(w http.ResponseWriter, r *http.Request, advisory *db.ManualAdvisory, previous db.ManualAdvisory, isEditing bool) {
	action := "advisory_create"
	auditDetails := manualAdvisoryAuditDetails(*advisory)
	if isEditing {
		action = "advisory_update"
		auditDetails = manualAdvisoryUpdateAuditDetails(previous, *advisory)
	}
	audit := h.adminAuditEntry(r, action, auditDetails)

	if err := h.upsertManualAdvisoryWithAudit(r, advisory, audit); err != nil {
		h.logger.Error("admin advisories: failed to save advisory", h.adminLogAttrs(r, "error", err, "id", advisory.ID)...)
		if errors.Is(err, db.ErrAdminAuditLog) {
			redirectAdvisoryError(w, r, web.Message("admin.advisories.error.audit_log"))
			return
		}
		if errors.Is(err, db.ErrConflict) {
			http.Redirect(w, r, adminAdvisoryURL(advisoryReturnOffset(r), url.Values{
				"edit": {advisory.ID},
				"err":  {web.Message("admin.advisories.error.conflict")},
			}), http.StatusSeeOther)
			return
		}
		if isEditing {
			redirectAdvisoryError(w, r, web.Message("admin.advisories.error.update"))
			return
		}
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.create"))
		return
	}

	msg := web.Message("admin.advisories.flash.created")
	if isEditing {
		msg = web.Message("admin.advisories.flash.updated")
	}
	http.Redirect(w, r, adminAdvisoryURL(advisoryReturnOffset(r), url.Values{"msg": {msg}}), http.StatusSeeOther)
}

func redirectAdvisoryError(w http.ResponseWriter, r *http.Request, message string) {
	http.Redirect(w, r, adminAdvisoryURL(advisoryReturnOffset(r), url.Values{"err": {message}}), http.StatusSeeOther)
}

func advisoryReturnOffset(r *http.Request) int {
	if r == nil {
		return 0
	}
	return parseNonNegativeOffset(r.PostForm.Get("return_offset"))
}

func adminAdvisoryURL(offset int, values url.Values) string {
	out := url.Values{}
	for key, vals := range values {
		for _, value := range vals {
			out.Add(key, value)
		}
	}
	if offset > 0 {
		out.Set("offset", strconv.Itoa(offset))
	}
	if len(out) == 0 {
		return "/admin/advisories"
	}
	return "/admin/advisories?" + out.Encode()
}

func normalizeAdvisoryFindingType(raw string) (string, bool) {
	findingType, ok := domain.ParseManualAdvisoryFindingType(raw)
	if !ok {
		return "", false
	}
	return string(findingType), true
}

func generateManualAdvisoryID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s%s-%s-%s-%s-%s",
		domain.ManualAdvisoryIDPrefix,
		encoded[0:8],
		encoded[8:12],
		encoded[12:16],
		encoded[16:20],
		encoded[20:32],
	), nil
}

func manualAdvisoryToView(advisory db.ManualAdvisory) manualAdvisoryView {
	updatedAt := ""
	if !advisory.UpdatedAt.IsZero() {
		updatedAt = advisory.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return manualAdvisoryView{
		ID:          advisory.ID,
		FindingType: advisory.FindingType,
		Ecosystem:   advisory.Ecosystem,
		Name:        advisory.Name,
		Severity:    advisory.Severity,
		RiskType:    advisory.RiskType,
		Summary:     advisory.Summary,
		Description: advisory.Description,
		UpdatedAt:   updatedAt,
	}
}

func manualAdvisoryInputToView(input manualAdvisoryInput) manualAdvisoryView {
	updatedAt := ""
	if !input.ExpectedUpdatedAt.IsZero() {
		updatedAt = input.ExpectedUpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	return manualAdvisoryView{
		ID:          input.ID,
		FindingType: input.FindingType,
		Ecosystem:   input.Ecosystem,
		Name:        input.Name,
		Severity:    input.Severity,
		RiskType:    input.RiskType,
		Summary:     input.Summary,
		Description: input.Description,
		UpdatedAt:   updatedAt,
	}
}

func invalidManualAdvisoryFindingType(view *manualAdvisoryView) string {
	if view == nil || view.FindingType == "" {
		return ""
	}
	switch view.FindingType {
	case "vulnerability", "malicious":
		return ""
	default:
		return view.FindingType
	}
}

func invalidManualAdvisoryEcosystem(view *manualAdvisoryView) string {
	if view == nil || view.Ecosystem == "" {
		return ""
	}
	switch view.Ecosystem {
	case "npm", "pypi", "go", "maven", "cargo", "nuget", "composer", "gem", "pub", "actions", "cocoapods", "swiftpm", "hex", "cran":
		return ""
	default:
		return view.Ecosystem
	}
}

func invalidManualAdvisorySeverity(view *manualAdvisoryView) string {
	if view == nil || view.Severity == "" {
		return ""
	}
	switch view.Severity {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return ""
	default:
		return view.Severity
	}
}

func (h *AdminHandler) listManualAdvisoryPage(ctx context.Context, offset int) ([]db.ManualAdvisory, bool, error) {
	limit := adminManualAdvisoryPageSize + 1
	var (
		advisories []db.ManualAdvisory
		err        error
	)
	if pager, ok := h.store.(manualAdvisoryPageLister); ok {
		advisories, err = pager.ListManualAdvisoriesPage(ctx, limit, offset)
	} else {
		advisories, err = h.store.ListManualAdvisories(ctx, offset+limit)
		if err == nil && offset > 0 {
			if offset >= len(advisories) {
				advisories = nil
			} else {
				advisories = advisories[offset:]
			}
		}
	}
	if err != nil {
		return nil, false, err
	}
	if len(advisories) > adminManualAdvisoryPageSize {
		return advisories[:adminManualAdvisoryPageSize], true, nil
	}
	return advisories, false, nil
}

func (h *AdminHandler) findManualAdvisoryByID(ctx context.Context, id string) (db.ManualAdvisory, bool, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return db.ManualAdvisory{}, false, nil
	}
	if getter, ok := h.store.(manualAdvisoryGetter); ok {
		advisory, err := getter.GetManualAdvisory(ctx, id)
		if err != nil {
			return db.ManualAdvisory{}, false, err
		}
		if advisory == nil {
			return db.ManualAdvisory{}, false, nil
		}
		return *advisory, true, nil
	}
	advisories, err := h.store.ListManualAdvisories(ctx, 500)
	if err != nil {
		return db.ManualAdvisory{}, false, err
	}
	for _, advisory := range advisories {
		if advisory.ID == id {
			return advisory, true, nil
		}
	}
	return db.ManualAdvisory{}, false, nil
}

func manualAdvisoryAuditDetails(advisory db.ManualAdvisory) map[string]string {
	return map[string]string{
		"id":           advisory.ID,
		"finding_type": advisory.FindingType,
		"ecosystem":    advisory.Ecosystem,
		"name":         advisory.Name,
		"severity":     advisory.Severity,
		"risk_type":    advisory.RiskType,
		"summary":      advisory.Summary,
		"description":  advisory.Description,
	}
}

func manualAdvisoryUpdateAuditDetails(previous, next db.ManualAdvisory) map[string]string {
	details := map[string]string{"id": next.ID}
	addManualAdvisoryAuditDetails(details, "previous_", previous)
	addManualAdvisoryAuditDetails(details, "new_", next)
	return details
}

func addManualAdvisoryAuditDetails(details map[string]string, prefix string, advisory db.ManualAdvisory) {
	details[prefix+"finding_type"] = advisory.FindingType
	details[prefix+"ecosystem"] = advisory.Ecosystem
	details[prefix+"name"] = advisory.Name
	details[prefix+"severity"] = advisory.Severity
	details[prefix+"risk_type"] = advisory.RiskType
	details[prefix+"summary"] = advisory.Summary
	details[prefix+"description"] = advisory.Description
}

func (h *AdminHandler) upsertManualAdvisoryWithAudit(r *http.Request, advisory *db.ManualAdvisory, audit *adminAuditEntry) error {
	ctx, cancel := h.adminAuditContext()
	defer cancel()
	if err := h.store.UpsertManualAdvisoryWithAudit(ctx, advisory, audit); err != nil {
		return fmt.Errorf("upsert manual advisory: %w", err)
	}
	return nil
}

func (h *AdminHandler) deleteManualAdvisoryWithAudit(r *http.Request, id string, audit *adminAuditEntry) error {
	ctx, cancel := h.adminAuditContext()
	defer cancel()
	if err := h.store.DeleteManualAdvisoryWithAudit(ctx, id, audit); err != nil {
		return fmt.Errorf("delete manual advisory: %w", err)
	}
	return nil
}

// HandleAdvisoryDelete handles POST /admin/advisories/delete.
func (h *AdminHandler) HandleAdvisoryDelete(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.requireAdminPost(w, r, adminPostGate{
		csrfAction:            "advisory_delete",
		bootstrapRedirectPath: "/admin/advisories",
	}); !ok {
		return
	}

	advisoryID := strings.TrimSpace(r.PostForm.Get("id"))
	if advisoryID == "" {
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.missing_id"))
		return
	}
	if strings.TrimSpace(r.PostForm.Get("confirm_id")) != advisoryID {
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.confirm_delete_id"))
		return
	}

	advisory, found, err := h.findManualAdvisoryByID(r.Context(), advisoryID)
	if err != nil {
		h.logger.Error("admin advisories: failed to load advisory before delete", h.adminLogAttrs(r, "error", err, "id", advisoryID)...)
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.load_delete"))
		return
	}
	if !found {
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.delete_not_found"))
		return
	}
	audit := h.adminAuditEntry(r, "advisory_delete", manualAdvisoryAuditDetails(advisory))

	if err := h.deleteManualAdvisoryWithAudit(r, advisoryID, audit); err != nil {
		h.logger.Error("admin advisories: failed to delete advisory", h.adminLogAttrs(r, "error", err, "id", advisoryID)...)
		if errors.Is(err, db.ErrAdminAuditLog) {
			redirectAdvisoryError(w, r, web.Message("admin.advisories.error.audit_log"))
			return
		}
		redirectAdvisoryError(w, r, web.Message("admin.advisories.error.delete"))
		return
	}
	http.Redirect(w, r, adminAdvisoryURL(advisoryReturnOffset(r), url.Values{"msg": {web.Message("admin.advisories.flash.deleted")}}), http.StatusSeeOther)
}

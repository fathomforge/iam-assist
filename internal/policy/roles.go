package policy

import "fmt"

// KnownRoles contains a curated subset of GCP predefined roles with their
// permission counts and descriptions. Used for offline validation and
// least-privilege suggestions.
//
// This is intentionally not exhaustive — it covers the most commonly
// requested roles. Run `iam-assist roles update` to fetch the full set
// from the GCP API.

// RoleInfo describes a predefined GCP role.
type RoleInfo struct {
	Role            string   `json:"role"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	PermissionCount int      `json:"permission_count"`
	Service         string   `json:"service"`
	NarrowerAlts    []string `json:"narrower_alternatives,omitempty"`
}

// KnownRolesDB is the offline role database.
var KnownRolesDB = map[string]RoleInfo{
	// ─── Primitive roles (always flag) ───
	"roles/owner":  {Role: "roles/owner", Title: "Owner", PermissionCount: 5000, Service: "resourcemanager", NarrowerAlts: []string{"use specific service roles"}},
	"roles/editor": {Role: "roles/editor", Title: "Editor", PermissionCount: 4000, Service: "resourcemanager", NarrowerAlts: []string{"use specific service roles"}},
	"roles/viewer": {Role: "roles/viewer", Title: "Viewer", PermissionCount: 2500, Service: "resourcemanager", NarrowerAlts: []string{"use specific service viewer roles"}},

	// ─── BigQuery ───
	"roles/bigquery.admin":      {Role: "roles/bigquery.admin", Title: "BigQuery Admin", PermissionCount: 52, Service: "bigquery", NarrowerAlts: []string{"roles/bigquery.dataEditor", "roles/bigquery.jobUser"}},
	"roles/bigquery.dataEditor": {Role: "roles/bigquery.dataEditor", Title: "BigQuery Data Editor", PermissionCount: 14, Service: "bigquery", NarrowerAlts: []string{"roles/bigquery.dataViewer"}},
	"roles/bigquery.dataViewer": {Role: "roles/bigquery.dataViewer", Title: "BigQuery Data Viewer", PermissionCount: 9, Service: "bigquery"},
	"roles/bigquery.dataOwner":  {Role: "roles/bigquery.dataOwner", Title: "BigQuery Data Owner", PermissionCount: 22, Service: "bigquery", NarrowerAlts: []string{"roles/bigquery.dataEditor"}},
	"roles/bigquery.jobUser":    {Role: "roles/bigquery.jobUser", Title: "BigQuery Job User", PermissionCount: 3, Service: "bigquery"},
	"roles/bigquery.user":       {Role: "roles/bigquery.user", Title: "BigQuery User", PermissionCount: 12, Service: "bigquery", NarrowerAlts: []string{"roles/bigquery.jobUser", "roles/bigquery.dataViewer"}},

	// ─── Cloud Storage ───
	"roles/storage.admin":          {Role: "roles/storage.admin", Title: "Storage Admin", PermissionCount: 17, Service: "storage", NarrowerAlts: []string{"roles/storage.objectAdmin"}},
	"roles/storage.objectAdmin":    {Role: "roles/storage.objectAdmin", Title: "Storage Object Admin", PermissionCount: 10, Service: "storage", NarrowerAlts: []string{"roles/storage.objectViewer", "roles/storage.objectCreator"}},
	"roles/storage.objectViewer":   {Role: "roles/storage.objectViewer", Title: "Storage Object Viewer", PermissionCount: 4, Service: "storage"},
	"roles/storage.objectCreator":  {Role: "roles/storage.objectCreator", Title: "Storage Object Creator", PermissionCount: 3, Service: "storage"},

	// ─── Compute Engine ───
	"roles/compute.admin":         {Role: "roles/compute.admin", Title: "Compute Admin", PermissionCount: 150, Service: "compute", NarrowerAlts: []string{"roles/compute.instanceAdmin.v1"}},
	"roles/compute.instanceAdmin.v1": {Role: "roles/compute.instanceAdmin.v1", Title: "Compute Instance Admin", PermissionCount: 55, Service: "compute", NarrowerAlts: []string{"roles/compute.viewer"}},
	"roles/compute.viewer":        {Role: "roles/compute.viewer", Title: "Compute Viewer", PermissionCount: 70, Service: "compute"},
	"roles/compute.networkAdmin":  {Role: "roles/compute.networkAdmin", Title: "Compute Network Admin", PermissionCount: 45, Service: "compute"},

	// ─── Cloud Run ───
	"roles/run.admin":     {Role: "roles/run.admin", Title: "Cloud Run Admin", PermissionCount: 25, Service: "run", NarrowerAlts: []string{"roles/run.developer"}},
	"roles/run.developer": {Role: "roles/run.developer", Title: "Cloud Run Developer", PermissionCount: 15, Service: "run", NarrowerAlts: []string{"roles/run.viewer"}},
	"roles/run.invoker":   {Role: "roles/run.invoker", Title: "Cloud Run Invoker", PermissionCount: 1, Service: "run"},
	"roles/run.viewer":    {Role: "roles/run.viewer", Title: "Cloud Run Viewer", PermissionCount: 8, Service: "run"},

	// ─── Cloud Functions ───
	"roles/cloudfunctions.admin":     {Role: "roles/cloudfunctions.admin", Title: "Cloud Functions Admin", PermissionCount: 20, Service: "cloudfunctions", NarrowerAlts: []string{"roles/cloudfunctions.developer"}},
	"roles/cloudfunctions.developer": {Role: "roles/cloudfunctions.developer", Title: "Cloud Functions Developer", PermissionCount: 12, Service: "cloudfunctions", NarrowerAlts: []string{"roles/cloudfunctions.viewer"}},
	"roles/cloudfunctions.viewer":    {Role: "roles/cloudfunctions.viewer", Title: "Cloud Functions Viewer", PermissionCount: 5, Service: "cloudfunctions"},

	// ─── IAM ───
	"roles/iam.securityAdmin":       {Role: "roles/iam.securityAdmin", Title: "Security Admin", PermissionCount: 35, Service: "iam"},
	"roles/iam.serviceAccountUser":  {Role: "roles/iam.serviceAccountUser", Title: "Service Account User", PermissionCount: 3, Service: "iam"},
	"roles/iam.serviceAccountAdmin": {Role: "roles/iam.serviceAccountAdmin", Title: "Service Account Admin", PermissionCount: 12, Service: "iam", NarrowerAlts: []string{"roles/iam.serviceAccountUser"}},
	"roles/iam.workloadIdentityUser": {Role: "roles/iam.workloadIdentityUser", Title: "Workload Identity User", PermissionCount: 1, Service: "iam"},

	// ─── Logging / Monitoring ───
	"roles/logging.admin":     {Role: "roles/logging.admin", Title: "Logging Admin", PermissionCount: 30, Service: "logging", NarrowerAlts: []string{"roles/logging.viewer"}},
	"roles/logging.viewer":    {Role: "roles/logging.viewer", Title: "Logs Viewer", PermissionCount: 8, Service: "logging"},
	"roles/monitoring.admin":  {Role: "roles/monitoring.admin", Title: "Monitoring Admin", PermissionCount: 40, Service: "monitoring", NarrowerAlts: []string{"roles/monitoring.viewer"}},
	"roles/monitoring.viewer": {Role: "roles/monitoring.viewer", Title: "Monitoring Viewer", PermissionCount: 15, Service: "monitoring"},

	// ─── Pub/Sub ───
	"roles/pubsub.admin":      {Role: "roles/pubsub.admin", Title: "Pub/Sub Admin", PermissionCount: 15, Service: "pubsub", NarrowerAlts: []string{"roles/pubsub.editor"}},
	"roles/pubsub.editor":     {Role: "roles/pubsub.editor", Title: "Pub/Sub Editor", PermissionCount: 10, Service: "pubsub", NarrowerAlts: []string{"roles/pubsub.publisher", "roles/pubsub.subscriber"}},
	"roles/pubsub.publisher":  {Role: "roles/pubsub.publisher", Title: "Pub/Sub Publisher", PermissionCount: 3, Service: "pubsub"},
	"roles/pubsub.subscriber": {Role: "roles/pubsub.subscriber", Title: "Pub/Sub Subscriber", PermissionCount: 4, Service: "pubsub"},
	"roles/pubsub.viewer":     {Role: "roles/pubsub.viewer", Title: "Pub/Sub Viewer", PermissionCount: 5, Service: "pubsub"},

	// ─── GKE ───
	"roles/container.admin":       {Role: "roles/container.admin", Title: "Kubernetes Engine Admin", PermissionCount: 80, Service: "container", NarrowerAlts: []string{"roles/container.developer"}},
	"roles/container.developer":   {Role: "roles/container.developer", Title: "Kubernetes Engine Developer", PermissionCount: 40, Service: "container", NarrowerAlts: []string{"roles/container.viewer"}},
	"roles/container.viewer":      {Role: "roles/container.viewer", Title: "Kubernetes Engine Viewer", PermissionCount: 20, Service: "container"},
	"roles/container.clusterAdmin": {Role: "roles/container.clusterAdmin", Title: "Kubernetes Engine Cluster Admin", PermissionCount: 30, Service: "container"},

	// ─── Secret Manager ───
	"roles/secretmanager.admin":          {Role: "roles/secretmanager.admin", Title: "Secret Manager Admin", PermissionCount: 12, Service: "secretmanager", NarrowerAlts: []string{"roles/secretmanager.secretAccessor"}},
	"roles/secretmanager.secretAccessor": {Role: "roles/secretmanager.secretAccessor", Title: "Secret Manager Secret Accessor", PermissionCount: 3, Service: "secretmanager"},
	"roles/secretmanager.viewer":         {Role: "roles/secretmanager.viewer", Title: "Secret Manager Viewer", PermissionCount: 5, Service: "secretmanager"},
}

// LookupRole returns the RoleInfo for a predefined role, or nil if unknown.
func LookupRole(role string) *RoleInfo {
	info, ok := KnownRolesDB[role]
	if !ok {
		return nil
	}
	return &info
}

// ValidateBindings checks bindings against the known role database and returns warnings.
func ValidateBindings(bindings []Binding) []string {
	var warnings []string

	for _, b := range bindings {
		info := LookupRole(b.Role)
		if info == nil {
			// Unknown role — might be custom or a role we don't track.
			continue
		}

		if len(info.NarrowerAlts) > 0 {
			warnings = append(warnings,
				fmt.Sprintf("%s (%d perms) has narrower alternatives: %v",
					b.Role, info.PermissionCount, info.NarrowerAlts))
		}

		if info.PermissionCount > 100 {
			warnings = append(warnings,
				fmt.Sprintf("%s grants %d permissions — consider a custom role with only needed permissions",
					b.Role, info.PermissionCount))
		}
	}

	return warnings
}

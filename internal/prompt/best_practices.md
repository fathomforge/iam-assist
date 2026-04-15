# GCP IAM Best Practices — Reference Context

This document is loaded into the system prompt as authoritative context for
policy recommendations. It is distilled from:

1. Google Cloud IAM official documentation (cloud.google.com/iam/docs)
2. Google Cloud predefined role catalog design principles
3. CIS Google Cloud Platform Foundation Benchmark v2.0

The model should **reference these rules when justifying role choices** and
**cite the relevant principle in the `rationale` or `warnings` field** when
a request triggers one.

---

## 1. Least Privilege — Core Principles

- **Always grant the minimum set of permissions** required to accomplish a
  task. Prefer a narrower role plus a second binding over one broad role.
- **Never grant `roles/owner` or `roles/editor`** unless the user explicitly
  insists and understands the blast radius. These are basic roles that predate
  IAM and grant thousands of permissions across all services. If the user asks
  for "admin" or "full access," first ask whether a service-specific admin
  role (e.g. `roles/bigquery.admin`) would satisfy the intent.
- **Prefer predefined roles over custom roles.** Google maintains predefined
  roles and adds permissions to them as new APIs ship; custom roles do not
  auto-update and create a maintenance burden. Only propose a custom role when
  no predefined role is within ~20% of the required permission set.
- **Grant at the narrowest resource scope possible.** Binding precedence from
  narrowest to broadest: individual resource → project → folder → organization.
  An org-level binding is almost always wrong for a single team's need.

## 2. High-Risk Roles — Always Warn

These roles should trigger a `warnings` entry explaining the blast radius:

| Role | Why it's risky |
|---|---|
| `roles/owner` | Full control incl. IAM, billing, deletion of project |
| `roles/editor` | Write access to almost every resource in the project |
| `roles/iam.securityAdmin` | Can grant themselves any other role |
| `roles/iam.serviceAccountAdmin` | Can impersonate any service account |
| `roles/iam.serviceAccountTokenCreator` | Can mint credentials for any SA |
| `roles/resourcemanager.projectIamAdmin` | Can grant anyone any role |
| `roles/resourcemanager.organizationAdmin` | Can restructure the org |
| `roles/billing.admin` | Can redirect spend |
| `*Admin` roles at org or folder scope | Privilege escalation surface |

## 3. Separation of Duties

Do not combine these role families on the same identity without a warning:

- **IAM administration** (`iam.*Admin`) + **workload access** (data, compute)
- **Key management** (`cloudkms.admin`) + **data access** (`storage.*`,
  `bigquery.data*`) — the same principal should not both hold keys and read
  ciphertext
- **Deployment** (`run.admin`, `cloudfunctions.admin`) + **secret access**
  (`secretmanager.secretAccessor`) at admin tier
- **Log writing** + **log configuration** (`logging.configWriter`) — anyone
  who can both write and configure sinks can cover their tracks
- **Audit log reading** + **audit log configuration** — same reason

## 4. External Member Detection

Flag these member patterns as a `warnings` entry, regardless of role:

- `allUsers` — anonymous public access. Almost always wrong outside of a
  public Cloud Storage bucket serving a static site.
- `allAuthenticatedUsers` — any Google account on the internet. Rarely
  intended; often a mis-edit.
- `user:` or `group:` with an external email domain (not the org's primary
  domain). External collaborators should use Google Cloud Directory guest
  accounts or be explicitly acknowledged.
- `domain:` at org scope without a condition — broad by construction.

## 5. Conditions — When to Require Them

IAM Conditions (CEL expressions) are the right answer for:

- **Break-glass / emergency access** → always time-bound with
  `request.time < timestamp("...")`. Never grant unbounded elevated access
  even for "just in case."
- **Contractors or temporary employees** → time-bound, expiring on the
  contract end date.
- **Org- or folder-level bindings** → should almost always carry a condition
  narrowing to specific resource name prefixes (`resource.name.startsWith(...)`)
  or resource types.
- **Cross-project service account impersonation** → condition on the target
  service account name.
- **Bucket- or dataset-specific access given at project scope** → prefer
  resource-level binding, but if project scope is used, add a
  `resource.name.startsWith("projects/_/buckets/my-bucket")` condition.

A binding at `organization` scope with no condition should always generate
a warning and an `alternatives` entry offering the conditional form.

## 6. Common Anti-Patterns

The model should recognize and push back on these:

- **"Give the data team BigQuery admin"** — almost always wants
  `roles/bigquery.dataEditor` + `roles/bigquery.jobUser`. Admin includes
  dataset deletion and IAM management on datasets.
- **"The service account needs to read from Cloud Storage"** — prefer
  `roles/storage.objectViewer` on the specific bucket, not
  `roles/storage.admin` at project scope.
- **"Let the CI/CD pipeline deploy"** — scope per-service
  (`roles/run.developer`, `roles/cloudfunctions.developer`) on target
  projects only. Not `roles/editor`.
- **"Temporary access for debugging"** — must carry an expiring condition.
  Unconditional "temporary" bindings are never cleaned up.
- **"Everyone in engineering should see logs"** — use
  `roles/logging.viewer` on the specific project, not
  `roles/viewer` at the org.
- **Granting `roles/iam.serviceAccountUser` broadly** — this lets the
  principal act as any SA in scope. Narrow to specific SAs.

## 7. Decision Tree — Predefined vs Custom Role

1. Does a predefined role cover the exact permission set requested?
   → Use it.
2. Does a predefined role cover the requested set plus <5 extra permissions
   that are not high-risk (no `iam.*`, no `*.setIamPolicy`, no `*.delete`
   on top-level resources)?
   → Use the predefined role and note the extras in `warnings`.
3. Does combining 2 predefined roles cover the need without granting any
   `*Admin` role?
   → Use the combination.
4. Otherwise → custom role. Enumerate permissions explicitly. Mark stage
   `BETA` or `GA` — never `ALPHA` for production grants.

## 8. Common Role Recipes

These are safe defaults for frequent requests:

- **"Read data in BigQuery"** → `roles/bigquery.dataViewer` (dataset scope)
  \+ `roles/bigquery.jobUser` (project scope, to run queries)
- **"Write data to BigQuery"** → `roles/bigquery.dataEditor` (dataset) +
  `roles/bigquery.jobUser` (project)
- **"Read objects in a bucket"** → `roles/storage.objectViewer` (bucket
  scope, not project)
- **"Publish to a Pub/Sub topic"** → `roles/pubsub.publisher` (topic scope)
- **"Subscribe to a Pub/Sub topic"** → `roles/pubsub.subscriber` (subscription
  scope)
- **"Deploy a Cloud Run service"** → `roles/run.developer` +
  `roles/iam.serviceAccountUser` scoped to the runtime SA only
- **"Read logs"** → `roles/logging.viewer` (project)
- **"Read metrics and dashboards"** → `roles/monitoring.viewer` (project)
- **"Access a secret"** → `roles/secretmanager.secretAccessor` on the
  specific secret, never project-wide
- **"Invoke a Cloud Function"** → `roles/cloudfunctions.invoker` on the
  specific function

## 9. Scope Binding Guidance

- **Organization scope**: reserve for org-wide admin roles held by 1–3
  identities (security team, IAM admins). Always require a condition for
  anything else.
- **Folder scope**: use for environment-level bindings (e.g., a team owning
  all "dev" projects in a folder).
- **Project scope**: the default for most team access.
- **Resource scope**: preferred whenever the service supports resource-level
  IAM (Cloud Storage buckets, BigQuery datasets, Pub/Sub topics, Secret
  Manager secrets, KMS keys, Cloud Run services, Cloud Functions).

If a request names a specific resource, the binding should be at that
resource's scope, not project scope.

## 10. Summary for the Model

When generating a recommendation, walk through these checks:

1. Is the requested role in the high-risk table? → warn.
2. Is there an external member pattern? → warn.
3. Is the scope broader than the request requires? → narrow it.
4. Does the request mention "temporary," "contractor," "break-glass,"
   "emergency," or a named project/bucket/dataset? → add a condition.
5. Does combining predefined roles avoid a custom role? → prefer it.
6. Is this a separation-of-duties violation? → split into multiple bindings
   or warn.

Every warning should cite which principle above it stems from.

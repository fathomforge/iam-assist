# iam-assist — Project Documentation

> AI-powered CLI that converts natural language access requests into least-privilege GCP IAM policies with Terraform output.

---

## 1. Project overview

**iam-assist** is an open-source Go CLI tool that takes plain-English access requests like *"Let the data team read BigQuery datasets in analytics-prod"* and produces production-ready, least-privilege GCP IAM policies. It optionally outputs Terraform HCL, runs a second-pass AI refinement to tighten permissions, and includes an interactive review flow for human approval before anything gets applied.

The tool is designed for platform engineers, SREs, and security teams who want to accelerate IAM policy authoring without sacrificing the principle of least privilege.

### Core capabilities

- **Natural language → IAM**: Describe access needs in English; get structured IAM bindings back.
- **Least-privilege by default**: The AI selects the narrowest predefined role. A second `--refine` pass tightens further.
- **Risk scoring**: Every recommendation is scored low / medium / high with explanations.
- **Terraform HCL output**: `--terraform` renders ready-to-apply `.tf` files with `google_project_iam_member`, `google_folder_iam_member`, `google_organization_iam_member`, and custom role resources.
- **Interactive review**: The `review` command walks users through approve / skip / edit for each binding.
- **Offline validation**: The `validate` command checks policies against a built-in role database — no API call needed.
- **Pluggable AI providers**: Anthropic Claude, OpenAI GPT, and Google Gemini — switch with a flag.
- **Pipe-friendly**: Colorized terminal output when interactive; JSON on stdout when piped.

---

## 2. Architecture

```
┌─────────────────────┐
│  Natural language    │   CLI args, stdin, or pipe
│  input               │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Cobra CLI router    │   generate · review · validate
│  cmd/                │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Prompt engine       │   System prompt + context hints
│  internal/prompt/    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐        ┌──────────────┐
│  Pluggable AI        │◄──────│  Refinement  │
│  provider            │──────►│  loop        │
│  internal/provider/  │        └──────────────┘
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  Policy parser +     │   JSON parse · role DB · risk scoring
│  risk assessment     │
│  internal/policy/    │
└──────────┬──────────┘
           │
     ┌─────┼─────┐
     ▼     ▼     ▼
  Terminal  JSON  Terraform HCL
```

### Data flow

1. User provides a natural language request via CLI argument, stdin, or pipe.
2. The Cobra router dispatches to the `generate`, `review`, or `validate` command.
3. The prompt engine wraps the request in a structured system prompt encoding GCP IAM best practices.
4. The pluggable provider sends the prompt to the configured AI backend and receives structured JSON.
5. The policy parser deserializes the response, runs risk assessment against the built-in role database, and optionally triggers a second refinement pass.
6. Output is rendered as colorized terminal display, raw JSON, or Terraform HCL depending on flags.

---

## 3. Project structure

```
iam-assist/
├── main.go                          Entry point
├── go.mod                           Module definition
├── Makefile                         Build, test, lint, smoke test
├── .goreleaser.yaml                 Cross-platform release config
├── .gitignore
├── LICENSE                          Apache 2.0
├── README.md                        User-facing documentation
├── configs/
│   └── example.yaml                 Sample configuration file
├── cmd/
│   ├── root.go                      Root Cobra command + Viper config
│   ├── generate.go                  NL → IAM generation command
│   ├── review.go                    Interactive review command
│   └── validate.go                  Offline validation command
└── internal/
    ├── provider/
    │   ├── provider.go              Provider interface + registry
    │   ├── anthropic.go             Anthropic Claude implementation
    │   ├── openai.go                OpenAI GPT implementation
    │   └── google.go                Google Gemini implementation
    ├── policy/
    │   ├── types.go                 IAM data model (Scope, Member, Binding, etc.)
    │   ├── types_test.go            Unit tests for parsing + risk assessment
    │   ├── generator.go             Two-pass generate → refine pipeline
    │   ├── roles.go                 Built-in GCP predefined role database (40+ roles)
    │   ├── roles_test.go            Unit tests for role validation
    │   └── format.go                Colorized terminal formatter
    ├── prompt/
    │   └── templates.go             System prompts + message builders
    └── terraform/
        ├── renderer.go              Go text/template HCL renderer
        └── renderer_test.go         Unit tests for Terraform output
```

**25 files, ~2,200 lines of Go.**

---

## 4. Technology choices

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go | Single binary, fast startup, strong CLI ecosystem |
| CLI framework | Cobra + Viper | Industry standard for Go CLIs; built-in flag parsing, config files, env var binding |
| AI interface | Pluggable provider pattern | Registry of constructors allows adding new backends without touching existing code |
| Default provider | Anthropic Claude (claude-sonnet-4) | Strong structured output, good at following JSON schemas |
| Terraform rendering | Go `text/template` | No external dependency; native support for conditionals and loops |
| Configuration | Viper (YAML + env vars) | Cascading config: file → env → flags |
| Release | GoReleaser | Cross-compile for linux/darwin/windows, amd64/arm64, Homebrew tap |
| License | Apache 2.0 | Permissive, enterprise-friendly |

---

## 5. Package details

### 5.1 `cmd/` — CLI commands

#### `root.go`

Sets up the root Cobra command, Viper configuration loading, and global flags:

- `--provider` (default: `anthropic`) — AI provider selection
- `--model` — model override (default per provider)
- `--api-key` — API key override
- `--config` — config file path (default: `~/.iam-assist.yaml`)

Config resolution order: CLI flag → environment variable → config file. Provider-specific env vars are supported: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GOOGLE_API_KEY`.

#### `generate.go`

The primary command. Accepts a natural language request and produces an IAM policy recommendation.

Flags:

- `--refine` — enables the two-pass refinement pipeline
- `--terraform` — outputs Terraform HCL instead of the default display
- `--json` — outputs raw JSON recommendation
- `-o, --out <file>` — writes output to a file
- `--context` — additional context hints (e.g., `--context 'project: analytics-prod'`)
- `--temperature` — AI temperature, 0.0–1.0 (default: 0.1)

Supports reading from stdin with `-` for piping:

```bash
echo "read BigQuery in analytics-prod" | iam-assist generate -
```

Auto-detects TTY: colorized terminal display when interactive, JSON when piped.

#### `review.go`

Interactive review flow for human approval. Loads a JSON policy recommendation and walks through each binding with options to approve, skip, edit the role, or quit. After review, optionally runs refinement and outputs the approved policy as JSON or Terraform.

```bash
iam-assist generate --json "admin access" | iam-assist review --terraform --out policy.tf
```

#### `validate.go`

Offline validation against the built-in GCP role database. Reports risk level, permission counts, and narrower alternatives. Exits with code 1 if the policy fails validation (high risk or many warnings).

```bash
iam-assist generate --json "storage admin" | iam-assist validate -
```

---

### 5.2 `internal/provider/` — Pluggable AI providers

#### Provider interface

```go
type Provider interface {
    Name() string
    Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}
```

A registry maps provider names to constructor functions. New providers are added with a single `Register()` call in `init()`.

#### Anthropic (`anthropic.go`)

- Default model: `claude-sonnet-4-20250514`
- Endpoint: `https://api.anthropic.com/v1/messages`
- Separates the system message from conversation messages (Anthropic's `system` field)
- Auth via `x-api-key` header

#### OpenAI (`openai.go`)

- Default model: `gpt-4o`
- Endpoint: `https://api.openai.com/v1/chat/completions`
- System message is passed inline as a `role: "system"` message
- Auth via `Authorization: Bearer` header

#### Google Gemini (`google.go`)

- Default model: `gemini-2.0-flash`
- Endpoint: `https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
- Maps `assistant` role to `model`, system message to `systemInstruction`
- Auth via `key` query parameter

All three implementations use raw `net/http` with no SDK dependency — the user can swap in official SDKs later if desired.

---

### 5.3 `internal/policy/` — Core data model and engine

#### Data types (`types.go`)

The central data model:

- **`Scope`** — where the binding applies: project, folder, organization, or resource-level. Carries type, ID, and display name.
- **`Member`** — a GCP IAM identity: user, group, serviceAccount, or domain. The `IAMIdentity()` method returns the canonical `type:email` format.
- **`Condition`** — optional IAM condition with title, description, and CEL expression.
- **`Binding`** — a single role binding: role name, list of members, optional condition.
- **`CustomRole`** — a GCP custom IAM role definition with ID, title, permissions list, and stage (GA/BETA/ALPHA).
- **`PolicyRecommendation`** — the full AI output: scope, bindings, rationale, warnings, alternatives, and optional custom role.

Parsing: `ParseRecommendation()` handles JSON deserialization with automatic stripping of markdown code fences (```` ```json ... ``` ````).

#### Risk assessment (`types.go`)

`Assess()` evaluates a `PolicyRecommendation` and returns a `RiskAssessment` with level and reasons:

- **High**: `roles/owner`, `roles/editor`, `roles/iam.securityAdmin`, `roles/iam.serviceAccountAdmin`, `roles/resourcemanager.projectIamAdmin`
- **Medium**: any role ending in `Admin`/`admin`, or org-level bindings without conditions
- **Low**: narrowly-scoped predefined or custom roles

#### Generator engine (`generator.go`)

`Generator` orchestrates the full pipeline:

1. Builds the prompt from the natural language request + optional context hints.
2. Calls the AI provider with low temperature (0.1) for deterministic output.
3. Parses the JSON response into a `PolicyRecommendation`.
4. If `--refine` is set, runs a second AI pass with the refinement prompt.
5. Returns the final recommendation.

The refinement pass serializes the first-pass recommendation back to JSON and sends it through a dedicated refinement prompt that checks for overly broad roles, scope reduction opportunities, missing conditions, separation of duties, and custom role opportunities.

#### Role database (`roles.go`)

A curated database of 40+ GCP predefined roles with:

- Permission count
- Service classification
- Narrower alternatives (e.g., `roles/bigquery.admin` → `roles/bigquery.dataEditor`, `roles/bigquery.jobUser`)

Coverage: BigQuery, Cloud Storage, Compute Engine, Cloud Run, Cloud Functions, IAM, Logging, Monitoring, Pub/Sub, GKE, Secret Manager, and the three primitive roles (owner/editor/viewer).

`ValidateBindings()` checks bindings against this database and returns warnings for roles with narrower alternatives or roles granting more than 100 permissions.

#### Terminal formatter (`format.go`)

Renders `PolicyRecommendation` as colorized terminal output with ANSI codes:

- Risk level with color coding (green/yellow/red)
- Binding details with role, members, and conditions
- Permission rationale
- Warnings and alternatives
- Custom role details when applicable

---

### 5.4 `internal/prompt/` — Prompt engineering

#### System prompt

The core system prompt encodes GCP IAM best practices:

**Principles:**

1. Least privilege — always choose the most restrictive role
2. Prefer predefined roles — only recommend custom roles when predefined are too broad
3. Scope narrowly — resource > project > folder > org
4. Warn on risk — flag elevated privileges, broad scopes, sensitive permissions
5. Conditional bindings — recommend IAM conditions when appropriate

**Role selection heuristics:**

| Verb pattern | Role family |
|---|---|
| read / view / list | Viewer roles (e.g., `roles/bigquery.dataViewer`) |
| write / create / update | Editor roles (e.g., `roles/bigquery.dataEditor`) |
| delete / manage / administer | Admin roles (with warnings) |
| deploy | Deployer/developer roles |
| monitor / observe | Monitoring viewer roles |
| debug / troubleshoot | Log viewer + diagnostic roles |

**Member inference rules:**

| Natural language | IAM member type |
|---|---|
| "the data team" | `group:data-team@<domain>` |
| "CI/CD pipeline" / "service account" | `serviceAccount:<name>@<project>.iam.gserviceaccount.com` |
| "everyone in the org" | `domain:<domain>` |
| Named person | `user:<email>` |

**Output contract:** The AI responds with only valid JSON matching the `PolicyRecommendation` schema — no markdown, no prose outside JSON.

#### Refinement prompt

Used for the second-pass refinement. Checks the initial recommendation against five criteria:

1. Could a narrower predefined role work?
2. Could the binding be scoped to a specific resource?
3. Should this have time-based, resource-name, or tag-based conditions?
4. Should this be split into multiple narrower bindings?
5. Would a custom role with only the needed permissions be better?

---

### 5.5 `internal/terraform/` — HCL renderer

Uses Go's `text/template` to produce Terraform HCL. Separate templates for:

- **Project-level bindings**: `google_project_iam_member`
- **Folder-level bindings**: `google_folder_iam_member`
- **Organization-level bindings**: `google_organization_iam_member`
- **Custom roles**: `google_project_iam_custom_role`

Each rendered file includes:

- Comment header with the original request
- Risk level annotation
- Warning comments
- Properly formatted resource blocks with conditions when present
- Custom role reference via `google_project_iam_custom_role.<id>.id` when applicable

Helper functions convert role names to Terraform resource names (e.g., `roles/bigquery.dataViewer` → `bigquery_data_viewer_0`).

---

## 6. Key design decisions

### Low temperature (0.1)

IAM policies are security-critical artifacts. The AI should not be creative with your permissions. Temperature 0.1 produces deterministic, consistent output across runs.

### Structured JSON contract

The system prompt specifies an exact JSON schema for the AI response. This avoids freeform text parsing and makes the output reliable across providers. Markdown code fences are stripped automatically as a safety net.

### Two-pass refinement

The initial generation optimizes for correctness — mapping the request to the right roles and members. The refinement pass optimizes for least privilege — questioning whether the initial recommendation is tighter than needed. This separation produces better results than trying to do both in a single prompt.

### Offline role database

The built-in role database enables validation without an API call. This is useful for CI/CD pipelines, air-gapped environments, and quick local checks. The database is intentionally curated (not exhaustive) — it covers the most commonly requested roles.

### Pipe-friendly design

Detecting TTY vs. pipe allows the tool to serve both interactive and scripted workflows. Colorized display for humans; clean JSON for machines. This enables chaining:

```bash
iam-assist generate --json "read BQ" | iam-assist validate - | iam-assist review --terraform --out policy.tf
```

### Registry-based provider pattern

Adding a new AI provider requires implementing one interface method and calling `Register()`. No switch statements, no factory functions to update. The pattern scales to community-contributed providers.

---

## 7. Configuration

### Config file (`~/.iam-assist.yaml`)

```yaml
provider: anthropic
org:
  domain: yourcompany.com
  default_project: my-default-project
defaults:
  refine: false
  temperature: 0.1
```

### Environment variables

| Variable | Description |
|---|---|
| `ANTHROPIC_API_KEY` | Anthropic Claude API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `GOOGLE_API_KEY` | Google Gemini API key |
| `IAM_ASSIST_PROVIDER` | Default provider override |
| `IAM_ASSIST_MODEL` | Default model override |

### Resolution order

CLI flag → `IAM_ASSIST_*` env var → provider-specific env var → config file value.

---

## 8. Usage examples

### Basic generation

```bash
iam-assist generate "Let the data team read BigQuery datasets in analytics-prod"
```

### With refinement

```bash
iam-assist generate --refine "Give CI/CD pipeline access to deploy Cloud Run services in staging"
```

### Terraform output to file

```bash
iam-assist generate --terraform --out policy.tf \
  "Storage viewer for etl-sa@myproject.iam.gserviceaccount.com"
```

### Stdin piping

```bash
echo "read access to GCS bucket my-data" | iam-assist generate -
```

### Full pipeline: generate → validate → review → Terraform

```bash
iam-assist generate --json "BigQuery admin for the analytics team" \
  | iam-assist validate - \
  && iam-assist generate --json "BigQuery admin for the analytics team" \
  | iam-assist review --terraform --out policy.tf
```

### Switch provider

```bash
iam-assist --provider openai generate "Pub/Sub publisher for the ingest service account"
iam-assist --provider google --model gemini-2.0-pro generate "Read logs in production"
```

### Additional context

```bash
iam-assist generate \
  --context "project: analytics-prod" \
  --context "domain: acme.com" \
  "Let the data team read BigQuery datasets"
```

---

## 9. Provider comparison

| Provider | Default model | Env variable | API style |
|---|---|---|---|
| Anthropic | `claude-sonnet-4-20250514` | `ANTHROPIC_API_KEY` | Messages API with separate system field |
| OpenAI | `gpt-4o` | `OPENAI_API_KEY` | Chat completions with system role |
| Google | `gemini-2.0-flash` | `GOOGLE_API_KEY` | generateContent with systemInstruction |

All providers use raw HTTP — no SDK dependency. Response formats are normalized into a common `CompletionResponse` struct with content, model name, and token usage.

---

## 10. Test coverage

### Policy types (`types_test.go`)

- Parses valid JSON into `PolicyRecommendation`
- Strips markdown code fences before parsing
- Returns error on invalid JSON
- Risk assessment: low for viewer roles, medium for admin roles, high for owner/editor, medium for org-level without conditions

### Role validation (`roles_test.go`)

- Looks up known roles correctly
- Returns nil for unknown roles
- Flags narrower alternatives for admin roles
- Flags broad permission counts (>100) for compute/owner roles

### Terraform renderer (`renderer_test.go`)

- Project-level binding with correct resource type, project ID, role, member
- Condition blocks render correctly
- Custom role resource renders with permissions list
- Organization-level binding uses `google_organization_iam_member` with `org_id`

### Running tests

```bash
make test
# or
go test -race -cover ./...
```

---

## 11. Build and install

### From source

```bash
git clone https://github.com/fathomforge/iam-assist.git
cd iam-assist
go mod tidy
go build -o iam-assist .
```

### Go install

```bash
go install github.com/fathomforge/iam-assist@latest
```

### Cross-platform release

```bash
goreleaser release --snapshot --clean
```

Produces binaries for linux/darwin/windows on amd64/arm64 via the `.goreleaser.yaml` config.

---

## 12. Roadmap

| Feature | Status | Description |
|---|---|---|
| `generate` command | Done | Core NL → IAM policy generation |
| Pluggable providers | Done | Anthropic, OpenAI, Google |
| Least-privilege refinement | Done | Two-pass AI refinement with `--refine` |
| Interactive review | Done | `review` command with approve/skip/edit |
| Terraform HCL output | Done | Project, folder, org bindings + custom roles |
| Offline validation | Done | `validate` command with built-in role DB |
| Risk assessment | Done | Automatic low/medium/high scoring |
| `audit` command | Planned | Analyze existing IAM bindings for over-privilege |
| `diff` command | Planned | Compare current vs. recommended policy |
| GCP org policy awareness | Planned | Respect organization policy constraints |
| Full predefined role DB | Planned | Fetch complete role set from GCP API |
| `--dry-run` with `terraform plan` | Planned | Integration with Terraform plan |
| GitHub Action | Planned | PR-based IAM review workflow |

---

## 13. Security considerations

- **No secrets in output**: API keys are never logged or included in generated output.
- **Low temperature**: Deterministic output reduces the chance of hallucinated permissions.
- **Risk scoring**: Every recommendation is automatically assessed before display.
- **Human review**: The `review` command ensures no policy is applied without explicit approval.
- **Offline validation**: The `validate` command catches common over-privilege patterns without network access.
- **High-risk role blocking**: The system prompt explicitly instructs the AI to never recommend `roles/owner` or `roles/editor` unless the user insists, and flags them as high-risk when they appear.
- **Condition recommendations**: The AI is instructed to recommend IAM conditions (time-based, resource-scoped) when appropriate, further narrowing access.

---

## 14. Contributing

The project uses standard Go tooling:

```bash
make build      # Build binary
make test       # Run tests with race detector
make lint       # Run golangci-lint
make smoke      # Quick end-to-end smoke test
```

Key contribution areas: additional predefined roles in the database, new AI provider implementations, Terraform output for additional resource types (e.g., `google_storage_bucket_iam_member`), and the planned `audit` / `diff` commands.

---

## 15. License

Apache License 2.0. See `LICENSE` file in the project root.

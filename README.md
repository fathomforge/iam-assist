# iam-assist

[![CI](https://github.com/fathomforge/iam-assist/actions/workflows/ci.yml/badge.svg)](https://github.com/fathomforge/iam-assist/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/fathomforge/iam-assist?sort=semver)](https://github.com/fathomforge/iam-assist/releases)
[![Go Reference](https://pkg.go.dev/badge/github.com/fathomforge/iam-assist.svg)](https://pkg.go.dev/github.com/fathomforge/iam-assist)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

> **Natural-language → least-privilege GCP IAM**, with Terraform output and an opinionated risk assessor. No telemetry. Bring your own LLM.

`iam-assist` turns plain-English access requests into IAM policies that follow Google Cloud's own best-practice playbook. It warns on high-risk roles, flags public/external members, insists on time-bound conditions for break-glass access, and renders ready-to-apply Terraform HCL so the recommendation is one `terraform apply` away from real.

```
$ iam-assist generate "Let the data team read BigQuery datasets in analytics-prod"

 IAM Policy Recommendation
────────────────────────────────────────────────────────────

Request: Let the data team read BigQuery datasets in analytics-prod
Scope:   analytics-prod (project: analytics-prod)
Risk:    low
          • bindings use narrowly-scoped predefined or custom roles

Bindings:
  1. roles/bigquery.dataViewer
     → group:data-team@yourcompany.com

Rationale:
  • bigquery.datasets.get: needed to list and read dataset metadata
  • bigquery.tables.getData: needed to read table contents via queries
```

## Features

- **Natural Language → IAM**: Describe what access you need in plain English
- **Least-Privilege by Default**: AI selects the narrowest predefined role; flags overly broad access
- **Two-Pass Refinement**: Optional `--refine` flag runs a second AI pass to tighten permissions
- **Risk Assessment**: Every recommendation is scored (low/medium/high) with reasons
- **Terraform Output**: `--terraform` flag renders ready-to-apply HCL with `google_project_iam_member` resources
- **Interactive Review**: `iam-assist review` walks you through approve/skip/edit for each binding
- **Pluggable AI Providers**: Anthropic Claude, OpenAI GPT, or Google Gemini — switch with a flag
- **Pipe-Friendly**: JSON on stdout when piped; colorized display in terminals

## Install

**Homebrew** (macOS / Linux):

```bash
brew install fathomforge/tap/iam-assist
```

**Prebuilt binary** (Linux / macOS / Windows, amd64 + arm64) — from the [latest release](https://github.com/fathomforge/iam-assist/releases/latest):

```bash
# Linux / macOS one-liner
curl -fsSL https://github.com/fathomforge/iam-assist/releases/latest/download/iam-assist_linux_amd64.tar.gz | tar -xz
sudo mv iam-assist /usr/local/bin/
iam-assist --version
```

**`go install`** (Go 1.24+):

```bash
go install github.com/fathomforge/iam-assist@latest
```

**From source:**

```bash
git clone https://github.com/fathomforge/iam-assist.git
cd iam-assist && go build -o iam-assist .
```

Every release ships SHA256 checksums in `checksums.txt`. Verify with `shasum -a 256 -c checksums.txt --ignore-missing`.

## Quick Start

```bash
# Set your preferred provider's API key
export ANTHROPIC_API_KEY=sk-ant-...
# or: export OPENAI_API_KEY=sk-...
# or: export GOOGLE_API_KEY=AI...

# Generate a policy
iam-assist generate "Give the CI/CD service account permission to deploy Cloud Run services in staging"

# With refinement
iam-assist generate --refine "Storage admin for the ETL pipeline"

# Output Terraform
iam-assist generate --terraform --out iam.tf "Read access to GCS bucket my-data for user alice@co.com"

# Interactive review
iam-assist generate --json "BigQuery admin for the analytics team" | iam-assist review --terraform --out policy.tf
```

## Usage

### `iam-assist generate`

```
iam-assist generate [flags] "natural language request"

Flags:
      --refine           run second-pass least-privilege refinement
      --terraform        output Terraform HCL
      --json             output raw JSON recommendation
  -o, --out string       write output to file
      --context strings  additional context hints
      --temperature      AI temperature 0.0-1.0 (default 0.1)
```

### `iam-assist review`

```
iam-assist review [flags] [policy.json]

Flags:
      --terraform    output approved policy as Terraform HCL
  -o, --out string   write approved output to file
```

### Global Flags

```
      --provider string   AI provider: anthropic, openai, google (default "anthropic")
      --model string      model override
      --api-key string    API key override
      --config string     config file (default ~/.iam-assist.yaml)
```

## How It Works

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────────┐
│  Natural Lang    │────▶│  AI Provider │────▶│  Policy Parser   │
│  Request         │     │  (pluggable) │     │  + Validator     │
└─────────────────┘     └──────────────┘     └────────┬─────────┘
                                                       │
                                              ┌────────▼─────────┐
                                              │  Risk Assessment │
                                              └────────┬─────────┘
                                                       │
                         ┌──────────────┐     ┌────────▼─────────┐
                         │  Refinement  │◀────│  Least-Privilege │
                         │  (optional)  │     │  Check           │
                         └──────┬───────┘     └──────────────────┘
                                │
              ┌─────────────────┼─────────────────┐
              ▼                 ▼                  ▼
      ┌──────────────┐ ┌──────────────┐  ┌──────────────┐
      │  Terminal    │ │  JSON        │  │  Terraform   │
      │  Display    │ │  Output      │  │  HCL         │
      └──────────────┘ └──────────────┘  └──────────────┘
```

### Prompt Engineering

The system prompt encodes GCP IAM best practices:
- Role selection heuristics map verbs (read/write/deploy/admin) to appropriate role families
- Member type inference resolves "the data team" → `group:`, "CI/CD pipeline" → `serviceAccount:`
- Conditional binding recommendations for time-limited or scoped access
- Structured JSON output schema for reliable parsing

### Risk Assessment

Every recommendation is automatically scored:
- **Low**: narrowly-scoped predefined roles
- **Medium**: admin-level roles or org-level bindings without conditions
- **High**: `roles/owner`, `roles/editor`, or security-admin roles

## Configuration

Create `~/.iam-assist.yaml`:

```yaml
provider: anthropic
org:
  domain: yourcompany.com
  default_project: my-default-project
defaults:
  refine: false
  temperature: 0.1
```

## Provider comparison

| Provider  | Default model     | Env variable        | Structured output |
|-----------|-------------------|---------------------|-------------------|
| Anthropic | `claude-sonnet-4` | `ANTHROPIC_API_KEY` | via prompt        |
| OpenAI    | `gpt-4o`          | `OPENAI_API_KEY`    | via prompt        |
| Google    | `gemini-2.5-flash`| `GOOGLE_API_KEY`    | **schema-enforced** |

Switch anytime with `--provider=anthropic|openai|google` or set `provider:` in `~/.iam-assist.yaml`. Override the model with `--model=...`.

## Privacy & data handling

- **No telemetry.** `iam-assist` does not phone home, does not write to any analytics endpoint, and has no hidden network calls. Audit it: `grep -r http ./internal`.
- **Your prompts go directly to the LLM provider you picked.** Over TLS. `iam-assist` is the only thing in the pipeline.
- **Your API key never leaves your machine** beyond the one request to the provider. It is passed via the `x-goog-api-key` / `x-api-key` / `Authorization` headers, never in URL query strings, and is redacted from transport-layer error messages as defense-in-depth.
- **Nothing is written to disk** unless you ask with `--out`, `--json`, or `--terraform`.
- **Reviewing the generated policy is on you.** `iam-assist` flags risks but is not a substitute for a human reading the Terraform before `apply`. The `review` command exists to make that step explicit.

See [SECURITY.md](SECURITY.md) for the full threat model and disclosure process.

## Roadmap

- [ ] `iam-assist audit` — analyze existing IAM bindings for over-privilege
- [ ] `iam-assist diff` — compare current vs. recommended policy
- [ ] GCP org policy constraints awareness
- [ ] Predefined role database for offline validation
- [ ] `--dry-run` with `terraform plan` integration
- [ ] GitHub Action for PR-based IAM reviews

## Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a PR.

## License

Apache 2.0 — see [LICENSE](LICENSE).

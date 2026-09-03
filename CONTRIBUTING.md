# Contributing to iam-assist

Thanks for considering a contribution. This doc covers the practical stuff —
what to build, how to run the tests, and how PRs get merged.

## What kinds of contributions are welcome

**Very welcome:**

- New role recipes in `internal/prompt/best_practices.md`
- New risk-assessor heuristics in `internal/policy/types.go`
- Terraform rendering improvements (more resource types, better condition
  handling, provider-version pinning)
- Bug reports with a minimal reproducer
- Documentation and example clarifications
- New example scenarios in `examples/`

**Please discuss first** (open an issue before a PR):

- New top-level commands
- New AI provider integrations
- Schema changes to `PolicyRecommendation`
- Anything that changes the default risk score for an existing test case

**Out of scope** (we'll politely decline):

- PRs that introduce telemetry or phone-home behavior
- Changes that require cloud credentials to test
- Large formatting/whitespace-only diffs

## Development setup

Prerequisites:

- Go 1.24 or later
- `make` (optional, for shortcuts)
- An API key for at least one supported provider if you want to run end-to-end

```bash
git clone https://github.com/fathomforge/iam-assist.git
cd iam-assist
go build -o iam-assist .
./iam-assist --version
```

Run tests:

```bash
go test -race ./...
```

Run against a real provider:

```bash
export GOOGLE_API_KEY=...
./iam-assist generate "read BigQuery datasets in project my-proj"
```

## Pull request checklist

Before you open a PR:

- [ ] `go test -race ./...` passes
- [ ] `go vet ./...` is clean
- [ ] New behavior has a test (table-driven is preferred — see `types_test.go`)
- [ ] If you touched risk scoring, you added a case to `TestAssess`
- [ ] If you touched Terraform rendering, you added a case to `renderer_test.go`
- [ ] Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)
      — the changelog is generated from them
- [ ] You're not introducing a new dependency unless strictly necessary; if
      you are, call it out in the PR body with a one-line justification

## Commit message format

We use Conventional Commits for automatic changelog generation:

- `feat(scope): add X` — new user-visible feature
- `fix(scope): handle Y` — bug fix
- `docs: ...` — docs-only change
- `test: ...` — test-only change
- `ci: ...` — workflow / pipeline change
- `chore: ...` — tooling, deps

Examples:

- `feat(risk): flag break-glass requests lacking time-bound conditions`
- `fix(terraform): escape quotes inside CEL expressions`
- `docs(README): add privacy statement`

## Releasing

Releases are cut by pushing a `v*` tag; `.github/workflows/release.yml` runs
GoReleaser, which builds the archives, uploads them to the GitHub release, and
generates the Homebrew cask.

Validate config changes locally before tagging:

```bash
goreleaser check
goreleaser release --snapshot --clean --skip=publish
```

### Homebrew tap (one-time setup)

The cask in `.goreleaser.yaml` only publishes once both of these exist:

1. A public repo `github.com/fathomforge/homebrew-tap` with a `Casks/`
   directory on its default branch (`main`).
2. A `HOMEBREW_TAP_GITHUB_TOKEN` secret on this repo — a PAT with
   `contents: write` on the tap. The workflow's default `GITHUB_TOKEN` cannot
   push to another repository.

Until then `skip_upload` evaluates to `true`, so GoReleaser writes the cask to
`dist/` and the release still succeeds. Users install with:

```bash
brew install --cask fathomforge/tap/iam-assist
```

## Review turnaround

Best-effort within a week. This is a small project — if you don't hear back
in 10 days, ping the PR with a comment.

## Code of conduct

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be kind, assume good intent,
focus on the code.

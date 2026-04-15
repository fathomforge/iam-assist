# Security policy

## Reporting a vulnerability

**Do not** open a public GitHub issue for security problems.

Email **security@fathomforge.dev** with:

- A description of the issue
- Steps to reproduce (a minimal test case is ideal)
- The affected version (`iam-assist --version`)
- Your assessment of the impact

We will acknowledge receipt within **72 hours** and aim to publish a fix or
mitigation within **14 days** for high-severity issues. If the issue is
severe enough to warrant a coordinated disclosure, we'll work with you on a
timeline.

If you don't hear back within 72 hours, re-send via
[GitHub Security Advisories](https://github.com/fathomforge/iam-assist/security/advisories/new).

## Scope

In scope:

- The `iam-assist` CLI itself (argument parsing, config handling, prompt
  construction, response parsing, Terraform rendering)
- The embedded best-practices reference that shapes LLM output
- Release artifacts and their supply chain (checksums, signatures)

Out of scope:

- Issues in upstream LLM providers (Anthropic, OpenAI, Google) — please
  report to them directly
- Issues in generated IAM recommendations being *suboptimal* (open a normal
  GitHub issue for these)
- Social engineering of the maintainer

## Threat model

`iam-assist` is a local CLI. It does not run a daemon, does not phone home,
and does not store data outside of files you explicitly write with `--out`.

Specific assumptions:

- **Your API key is a secret.** `iam-assist` reads it from env / config /
  flag and only sends it to the provider you picked. We never log keys and
  redact them from transport errors as defense-in-depth.
- **Your prompts are a secret.** They are transmitted directly to the LLM
  provider over TLS and nowhere else. There is no telemetry.
- **Generated policies must be reviewed before applying.** `iam-assist`
  flags risks but is not a substitute for human review of IAM changes. The
  `review` command exists to make this step explicit.

Issues worth reporting even though they aren't "classic" vulns:

- Ways to trick the tool into emitting invalid or dangerous Terraform
- Ways to inject content into the LLM prompt that bypasses least-privilege
  guidance
- Ways to exfiltrate the API key via crafted input
- Cases where `iam-assist` accepts obviously wrong policies without warning

## Supply chain

Release binaries are built via GoReleaser from tagged commits on `main`
through a GitHub Actions workflow. Every release publishes a `checksums.txt`
file. Verify downloads against it:

```
shasum -a 256 -c checksums.txt --ignore-missing
```

Signed releases (cosign) are on the roadmap and will be announced when ready.

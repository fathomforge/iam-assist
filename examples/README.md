# Examples

Six canonical scenarios showing what `iam-assist` generates for common
requests. Each example has:

- `*.request.txt` — the plain-English input
- `*.json` — the structured `PolicyRecommendation` (what the LLM returns
  after schema-enforced decoding)
- `*.tf` — the rendered Terraform HCL

You can regenerate any of them against your preferred provider:

```bash
iam-assist generate --json "$(cat examples/01-bigquery-read.request.txt)" \
  > examples/01-bigquery-read.json

iam-assist review examples/01-bigquery-read.json --terraform \
  -o examples/01-bigquery-read.tf
```

Or pipe the included JSON through `validate` / `review` to exercise the
offline pipeline without touching an API:

```bash
iam-assist validate examples/01-bigquery-read.json
iam-assist review  examples/01-bigquery-read.json
```

## Index

| # | Scenario | Risk | Highlights |
|---|---|---|---|
| 01 | [BigQuery dataset read for a team](01-bigquery-read.json) | low | `dataViewer` + `jobUser`, no admin |
| 02 | [GCS bucket object write for a service account](02-gcs-sa-write.json) | low | bucket-scoped `objectCreator` |
| 03 | [Cloud Run deploy from CI/CD](03-cicd-cloud-run.json) | low | `run.developer` + scoped SA impersonation |
| 04 | [Contractor time-bound BigQuery access](04-contractor-timebound.json) | medium | `request.time < timestamp(...)` condition, external-member warning |
| 05 | [Break-glass SA impersonation with CEL condition](05-breakglass-impersonation.json) | high | `tokenCreator` + resource.name CEL pin + warning |
| 06 | [Read-only Pub/Sub subscription for analytics](06-pubsub-subscriber.json) | low | topic-scoped `subscriber`, minimal surface |

Each example is hand-curated to be deterministic and reviewable — no live
LLM output. They also serve as regression fixtures for the assessor and
renderer.

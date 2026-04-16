package prompt

import (
	_ "embed"
	"fmt"
	"strings"
)

// bestPracticesDoc is the curated GCP IAM best-practices reference loaded
// into every system prompt as RAG context. Source: internal/prompt/best_practices.md.
//
//go:embed best_practices.md
var bestPracticesDoc string

// systemPromptWithContext returns the core system prompt with the embedded
// best-practices reference appended.
func systemPromptWithContext() string {
	return SystemPrompt + "\n\n---\n\nREFERENCE: GCP IAM BEST PRACTICES\n\nThe following is authoritative reference material. Apply these rules when choosing roles, scopes, members, and conditions. Cite the relevant principle in `rationale` or `warnings` when a request triggers one.\n\n" + bestPracticesDoc
}

// SystemPrompt is the core system prompt for NL → IAM conversion.
const SystemPrompt = `You are an expert GCP IAM security engineer. Your job is to convert natural language access requests into least-privilege IAM policy recommendations.

CRITICAL PRINCIPLES:
1. LEAST PRIVILEGE: Always choose the most restrictive role that satisfies the request. Never recommend roles/owner or roles/editor unless the user explicitly insists.
2. PREFER PREDEFINED ROLES: Use Google's predefined roles when they closely match. Only recommend custom roles when predefined roles are too broad.
3. SCOPE NARROWLY: Bind at the narrowest resource scope possible (resource > project > folder > org). When the request names a specific BigQuery dataset/table, GCS bucket, Pub/Sub topic, Secret Manager secret, or Cloud Run service, emit scope.type = "resource" and fill in scope.resource_type with the correct kind (bigquery_dataset, bigquery_table, storage_bucket, pubsub_topic, secret_manager_secret, cloud_run_service). DO NOT put a resource path into a project-scoped binding — scope.id for a project binding must be a bare project id. For a dataset binding, scope.id is the dataset id and scope.project is the owning project.
4. WARN ON RISK: Flag any elevated privileges, broad scopes, or sensitive permissions.
5. CONDITIONAL BINDINGS: Recommend IAM conditions when appropriate (time-based, resource-name, etc).

RESPONSE FORMAT:
Respond with ONLY valid JSON matching this exact schema (no markdown, no explanation outside JSON):

{
  "scope": {
    "type": "project|folder|organization|resource",
    "id": "<primary id: project id, folder number, org id, or — for resource scope — the resource's own id: dataset_id, table_id, bucket name, topic, secret_id, or cloud run service name>",
    "display": "<human-readable label>",
    "resource_type": "<REQUIRED when type=resource. One of: bigquery_dataset, bigquery_table, storage_bucket, pubsub_topic, secret_manager_secret, cloud_run_service>",
    "project":       "<parent project id for resource scopes that need one (all except storage_bucket)>",
    "location":      "<region, REQUIRED for cloud_run_service>",
    "parent":        "<dataset_id, REQUIRED for bigquery_table>"
  },
  "bindings": [
    {
      "role": "roles/...",
      "members": [
        {
          "type": "user|group|serviceAccount|domain",
          "email": "<identity>",
          "display": "<optional label>"
        }
      ],
      "condition": {
        "title": "<short title>",
        "description": "<what this condition does>",
        "expression": "<CEL expression>"
      }
    }
  ],
  "rationale": [
    {
      "permission": "<specific permission>",
      "reason": "<why this permission is needed>"
    }
  ],
  "warnings": ["<any security concerns>"],
  "alternatives": ["<narrower or broader alternatives the user might consider>"],
  "uses_custom_role": false,
  "custom_role": null
}

ROLE SELECTION HEURISTICS:
- "read" / "view" / "list" → viewer roles (e.g., roles/bigquery.dataViewer)
- "write" / "create" / "update" → editor roles (e.g., roles/bigquery.dataEditor)
- "delete" / "manage" / "administer" → admin roles (warn about breadth)
- "deploy" → specific deployer/developer roles
- "monitor" / "observe" → monitoring viewer roles
- "debug" / "troubleshoot" → log viewer + relevant diagnostic roles

MEMBER INFERENCE:
- "the data team" → group:data-team@<domain> (ask user to confirm domain)
- "CI/CD pipeline" / "service account" → serviceAccount:<name>@<project>.iam.gserviceaccount.com
- "everyone in the org" → domain:<domain>
- Named person → user:<email>
- If identity is ambiguous, use a placeholder and add a warning.

OMIT the "condition" field entirely when no condition is recommended. NEVER set "condition" to an object whose fields contain the literal string "null" — leave the field out of the binding instead.

NEVER emit the literal string "null" as a value anywhere in the JSON response. If a field has no value, omit it entirely or use an empty array/object. String fields must carry real content or be absent.`

// RefinementPrompt is used for the second-pass least-privilege refinement.
const RefinementPrompt = `You are reviewing a GCP IAM policy recommendation for least-privilege compliance.

Given the ORIGINAL REQUEST and the PROPOSED POLICY below, analyze whether the policy grants more access than needed. If so, suggest a tighter alternative.

Check for:
1. OVERLY BROAD ROLES: Could a narrower predefined role work? List the specific permissions needed vs. what the role grants.
2. SCOPE REDUCTION: Could the binding be scoped to a specific resource instead of project-level?
3. MISSING CONDITIONS: Should this have time-based, resource-name, or tag-based conditions?
4. SEPARATION OF DUTIES: Should this be split into multiple, narrower bindings?
5. CUSTOM ROLE OPPORTUNITY: If no predefined role is a close fit, define a custom role with only the needed permissions.

Respond with the same JSON schema. Set "uses_custom_role": true and populate "custom_role" if you recommend one. Update "rationale" to explain each refinement decision. Add to "warnings" if the original was over-privileged.`

// BuildGenerateMessages constructs the message list for the initial generation.
func BuildGenerateMessages(request string, context ...string) []Message {
	messages := []Message{
		{Role: "system", Content: systemPromptWithContext()},
	}

	userContent := request
	if len(context) > 0 {
		userContent = fmt.Sprintf("Context:\n%s\n\nAccess request: %s",
			strings.Join(context, "\n"), request)
	}

	messages = append(messages, Message{Role: "user", Content: userContent})
	return messages
}

// BuildRefineMessages constructs the message list for the refinement pass.
func BuildRefineMessages(originalRequest string, proposedPolicy string) []Message {
	return []Message{
		{Role: "system", Content: RefinementPrompt + "\n\n---\n\nREFERENCE: GCP IAM BEST PRACTICES\n\n" + bestPracticesDoc},
		{Role: "user", Content: fmt.Sprintf(
			"ORIGINAL REQUEST:\n%s\n\nPROPOSED POLICY:\n%s\n\nPlease refine this for least privilege. Respond with ONLY valid JSON.",
			originalRequest, proposedPolicy,
		)},
	}
}

// Message mirrors the provider message type to avoid circular imports.
type Message struct {
	Role    string
	Content string
}

// ToProviderMessages converts prompt messages to provider messages.
func ToProviderMessages(msgs []Message) []struct {
	Role    string
	Content string
} {
	out := make([]struct {
		Role    string
		Content string
	}, len(msgs))
	for i, m := range msgs {
		out[i].Role = m.Role
		out[i].Content = m.Content
	}
	return out
}

# LLM-Powered Triage

PledgeRecon can send vulnerability findings to an LLM for automated triage, dramatically reducing false positives.

## The Problem

Version-based vulnerability matching produces false positives:
- Dev-only dependencies flagged as production risks
- Unreachable vulnerable functions treated as critical
- Mitigated vulnerabilities (sandboxing, input validation) re-reported
- Version ranges that don't actually apply

## The Solution

PledgeRecon sends the full vulnerability context to an LLM and asks it to assess whether the finding is a true positive or false positive:

```
┌─────────────────────────────────────────────────────────┐
│                  Triage Pipeline                         │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Finding + Advisory + Reachability + Call Chain         │
│                    ↓                                    │
│  Build structured prompt                                │
│    - Advisory ID, summary, description                  │
│    - Severity, CVSS score                               │
│    - Package, version, fix info                         │
│    - Reachability status, call chain                    │
│    - Vulnerable functions                               │
│    - CWEs                                               │
│                    ↓                                    │
│  Send to LLM provider                                   │
│    - OpenAI (gpt-4o-mini)                               │
│    - Anthropic (Claude)                                 │
│    - Ollama (local models)                              │
│    - llama.cpp (local, no server needed)                │
│    - Fine-tuned models (custom endpoints)               │
│    - Custom endpoint                                    │
│                    ↓                                    │
│  Parse JSON response                                    │
│    - verdict: confirmed / false_positive / inconclusive │
│    - confidence: 0.0 - 1.0                              │
│    - explanation: human-readable reasoning              │
│    - remediation: recommended fix                       │
│                    ↓                                    │
│  Update finding status                                  │
│    - Confirmed → stays in report                        │
│    - FalsePositive → filtered from CI blocking          │
│    - Inconclusive → stays but flagged for review        │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

## LLM Providers

### OpenAI (default)
```toml
[triage_config]
provider = "openai"
api_key = "sk-..."  # Or set via environment
model = "gpt-4o-mini"
max_tokens = 1024
```

### Anthropic
```toml
[triage_config]
provider = "anthropic"
api_key = "sk-ant-..."
model = "claude-sonnet-4-20250514"
max_tokens = 1024
```

### Ollama (self-hosted, no API key needed)
```toml
[triage_config]
provider = "ollama"
model = "llama3"
endpoint = "http://localhost:11434/api/generate"
max_tokens = 1024
```

### llama.cpp (Goal 39 — local model, no server required)
```toml
[triage_config]
provider = "llamacpp"
model = "llama-3-8b"
llamacpp_model_path = "/path/to/ggml-model.bin"
endpoint = "http://localhost:8080/completion"  # llama.cpp server endpoint
max_tokens = 1024
```

### Fine-tuned models (Goal 40)
```toml
[triage_config]
provider = "local"
model = "pledgerecon-triage-v1"
fine_tuned_model_path = "/path/to/fine-tuned-model"
endpoint = "http://localhost:8000/v1/chat/completions"
max_tokens = 1024
```

### Custom endpoint
```toml
[triage_config]
provider = "custom"
api_key = "your-key"
model = "your-model"
endpoint = "https://your-llm-endpoint.com/v1/chat/completions"
max_tokens = 2048
```

## Prompt Structure

The triage prompt includes:

1. **Role**: "You are a security analyst triaging a dependency vulnerability finding."
2. **Vulnerability context**: Advisory ID, summary, description, severity, CVSS
3. **Package context**: Package name, version, fix availability, fix version
4. **Reachability**: Whether the vulnerable function is reachable, call chain
5. **CWEs**: Associated weakness classifications
6. **Task**: Assess exploitability considering reachability, dev-only status, mitigating factors
7. **Output format**: JSON with verdict, confidence, explanation, remediation

### Custom Prompt Templates (Goal 41)

You can customize the triage prompt using template variables:

```toml
[triage_config]
prompt_template = "Analyze {advisory_id} for {package}@{version} (severity: {severity}, reachability: {reachability}). Vulnerable functions: {vuln_funcs}. Call chain: {call_chain}."
```

Available template variables:

| Variable | Description |
|---|---|
| `{advisory_id}` | CVE/GHSA identifier |
| `{package}` | Package name |
| `{version}` | Installed version |
| `{severity}` | Vulnerability severity |
| `{reachability}` | Reachability status |
| `{vuln_funcs}` | Comma-separated vulnerable functions |
| `{call_chain}` | Arrow-separated call chain |

## Verdict Types

| Verdict | Meaning | CI Behavior |
|---|---|---|
| `confirmed` | True positive — vulnerability is real and exploitable | Blocks CI |
| `false_positive` | Not exploitable in this context | Filtered from CI blocking |
| `inconclusive` | LLM could not determine with confidence | Stays in report, flagged for human review |

## Confidence Scoring

The LLM returns a confidence score (0.0 to 1.0):
- **> 0.8**: High confidence — verdict is likely correct
- **0.5 - 0.8**: Medium confidence — human review recommended
- **< 0.5**: Low confidence — finding stays as-is

### Confidence Threshold (Goal 42)

Configure a threshold below which false-positive verdicts are **not** auto-applied. This prevents the LLM from suppressing findings when it's uncertain:

```toml
[triage_config]
confidence_threshold = 0.8  # Default: 0.8
```

A false-positive verdict with confidence below the threshold is treated as `inconclusive` instead, requiring human review.

## Batch Triage (Goal 36)

PledgeRecon can send multiple findings in a single LLM call to reduce API costs and latency:

```toml
[triage_config]
batch_size = 5  # Default: 5 findings per batch
```

When `batch_size > 1`, findings are grouped into batches and sent as a single prompt. The LLM is asked to return a JSON array of results, one per finding. This reduces API calls by up to 5x.

```rust
let engine = TriageEngine::new(config.triage_config);
let results = engine.triage_batch(&findings);
engine.apply_triage(&mut findings, &results);
```

## Response Caching (Goal 37)

Triage results are cached to avoid redundant LLM calls across scans:

```toml
[triage_config]
enable_cache = true              # Default: true
cache_dir = ".pledgerecon/cache"  # Default: .pledgerecon/triage-cache
```

Caching is keyed by a deterministic hash of the finding (advisory ID, package, version, reachability, call chain). Both in-memory and disk caches are used — disk cache persists across runs.

## Streaming Responses (Goal 38)

For real-time feedback, PledgeRecon can stream LLM responses via Server-Sent Events (SSE):

```toml
[triage_config]
stream = true  # Default: false
```

Streaming is supported for OpenAI-compatible endpoints. The full response is assembled from streamed chunks before parsing.

## Multi-Model Consensus (Goal 43)

Query multiple LLMs and use majority voting to increase triage accuracy:

```toml
[triage_config]
provider = "openai"
model = "gpt-4o-mini"
consensus_models = [
  "anthropic:claude-sonnet-4-20250514",
  "ollama:llama3",
]
```

When `consensus_models` is non-empty, each finding is sent to all listed models. The final verdict is determined by majority vote. If models disagree, the highest confidence result wins.

## Audit Logging (Goal 44)

Log all LLM triage calls for compliance and debugging:

```toml
[triage_config]
audit_log = true
audit_log_path = ".pledgerecon/audit.jsonl"
```

Each audit entry includes:
- Timestamp (ISO 8601)
- Finding ID (CVE/GHSA)
- Model used
- Prompt hash (for deduplication)
- Verdict and confidence
- Token usage (input/output)
- Cost (USD)
- Whether the result was cached

Audit logs are written in JSONL format (one JSON object per line) and flushed at the end of each scan.

## Cost Tracking (Goal 45)

Track token usage and cost per scan:

```toml
[triage_config]
cost_tracking = true
cost_per_input_token = 0.00001   # Per-token cost (default: $0.01/1M tokens)
cost_per_output_token = 0.00003  # Per-token cost (default: $0.03/1M tokens)
```

At the end of each scan, a cost summary is logged:

```
Triage cost: 15 calls, 7500 input tokens, 1200 output tokens, $0.1110 USD
```

## Privacy Considerations

- **No source code sent**: Only vulnerability metadata is sent to the LLM
- **No secrets sent**: Package names, versions, and advisory text only
- **Self-hosted option**: Use Ollama or llama.cpp for fully local triage (no data leaves your machine)
- **API keys**: Stored in `pledgerecon.toml` or environment variables, never logged

## Cost Estimation

Using `gpt-4o-mini` at ~$0.15/1M input tokens:
- Average prompt: ~500 tokens
- Average response: ~200 tokens
- Cost per finding: ~$0.0001
- 100 findings: ~$0.01
- 1000 findings: ~$0.10

With batch triage (batch_size=5), costs are reduced further:
- 100 findings: ~$0.02 (20 batch calls instead of 100 individual calls)
- 1000 findings: ~$0.20

With caching enabled, repeat scans of unchanged projects cost $0.

## CLI Usage

```bash
# Enable triage
pledgerecon scan . --triage

# With configuration in pledgerecon.toml
pledgerecon scan .  # triage = true in config
```

## Error Handling

If the LLM call fails (network error, rate limit, invalid response):
- Finding status is set to `Inconclusive`
- Error message is stored in `triage_explanation`
- Scan continues — triage failures don't block the scan
- Failed calls are still logged in the audit log (if enabled)

# Optional Local AI Assistant

`peperspray` can use a local Ollama-compatible assistant to explain access
events and policy-review candidates. The assistant is advisory only.

It is disabled by default, never used by `pepersprayd`, and never participates
in allow/deny decisions.

## What It Does

- checks local assistant availability with `peperspray assistant doctor`
- explains a selected event with `peperspray why last --assist`
- reviews learned policy candidates with `peperspray policy-review --assist`
- applies deterministic redaction before sending metadata to the local endpoint
- renders deterministic command output first, then assistant commentary
- prints assistant progress to stderr while the local model is processing

## What It Does Not Do

- read or send credential file contents
- call cloud LLM providers
- modify `/etc/peperspray/config.toml`
- apply policy suggestions
- run model-suggested commands
- replace deterministic `why`, `logs`, `policy-review`, or `policy-apply`

## Recommended Models

The default model is `gemma4:12b`, which is the preferred v1 quality choice for
16GB VRAM local workstations such as Radeon RX 6800 XT systems.

This assistant works best with fast instruction-following models that return
short structured output. It does not need a large reasoning model because
`peperspray` already performs deterministic event selection, grouping,
redaction, policy checks, and risk hint generation.

Recommended order:

1. `gemma4:12b`
2. `qwen3:14b`
3. `qwen3.5:latest`
4. `qwen3:8b`
5. `llama3.1:8b`
6. `mistral:7b`
7. any local Ollama model you explicitly choose

Smaller non-reasoning models can be a good fit if they reliably follow JSON
instructions. The best model for this feature is the one that quickly returns a
short, conservative, parseable review.

For Ollama chat requests, `peperspray` asks the provider to disable
thinking/reasoning output. This keeps responses faster and avoids models
returning hidden reasoning instead of final assistant content.

The CLI does not pull models automatically:

```sh
ollama pull gemma4:12b
```

## Configuration

Assistant preferences are user-level and separate from the root-owned security
policy:

```text
~/.config/peperspray/assistant.toml
```

Example:

```toml
provider = "ollama"
endpoint = "http://127.0.0.1:11434"
model = "gemma4:12b"
timeout_seconds = 30
max_events = 20
redaction = "balanced"
```

CLI flags override this file:

```sh
peperspray assistant doctor --assistant-model qwen3:14b
```

## Commands

Check provider and model availability:

```sh
peperspray assistant doctor
```

Explain the latest event:

```sh
peperspray why last --assist
```

Review learned access candidates:

```sh
peperspray policy-review --assist
```

While a local model is generating, progress is written to stderr:

```text
Assistant: reviewing policy candidates with local model 'gemma4:12b' at http://127.0.0.1:11434 (timeout: 30s)...
```

This keeps stdout suitable for normal display or `--assistant-json` parsing.

Shared assistant flags:

```text
--assistant-provider ollama
--assistant-endpoint http://127.0.0.1:11434
--assistant-model gemma4:12b
--assistant-timeout 30
--assistant-redaction strict|balanced|none
--assistant-json
```

## Redaction Modes

`strict` sends minimal metadata: executable basename, protected group,
operation, decision, and heavily reduced process context.

`balanced` is the default. It replaces the home directory with `~`, keeps useful
process paths, and redacts obvious token/password/secret patterns in command
metadata.

`none` sends raw event metadata to the configured local endpoint. Use it only
when you trust the endpoint and understand the metadata being sent.

The assistant never receives credential file contents.

## Troubleshooting

If the endpoint is unavailable:

```text
Assistant unavailable: could not connect to http://127.0.0.1:11434.
Run `peperspray assistant doctor` for details.
```

If the model is missing:

```text
Assistant model not found: gemma4:12b. Install it with: ollama pull gemma4:12b
```

If the model returns non-JSON text, `peperspray` shows a parsing warning and the
raw assistant text. The deterministic command output remains valid.

`peperspray` also tolerates common local-model formatting mistakes, including
Markdown code fences, capitalized risk levels, object-valued guidance, and some
JSON-like output with unquoted keys. If the response still cannot be normalized,
the raw assistant text is shown with a warning.

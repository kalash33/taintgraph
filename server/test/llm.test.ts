import { test } from "node:test";
import assert from "node:assert/strict";
import { llmFromEnv, openAiCompatible, parseArgs, stripThinking } from "../src/agents/llm.ts";
import { validate } from "../src/agents/analyst.ts";

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });

test("tool arguments: JSON string, object, broken JSON, junk", () => {
  assert.deepEqual(parseArgs('{"name":"chalk"}'), { name: "chalk" });
  assert.deepEqual(parseArgs({ name: "chalk" }), { name: "chalk" });
  assert.deepEqual(parseArgs('Sure! {"login":"qix"} hope that helps'), { login: "qix" });
  assert.deepEqual(parseArgs("not json"), {});
  assert.deepEqual(parseArgs("[1,2]"), {});
  assert.deepEqual(parseArgs(undefined), {});
});

test("reasoning is stripped from answers", () => {
  assert.equal(stripThinking("<think>hmm, chalk</think>chalk@5.6.1 is malware."), "chalk@5.6.1 is malware.");
  assert.equal(stripThinking("thinking without an opening tag</think>Answer."), "Answer.");
  assert.equal(stripThinking("ansi\u2011regex@6.2.1"), "ansi-regex@6.2.1");
});

test("provider is picked from the environment", () => {
  assert.equal(llmFromEnv({}), null);
  assert.match(llmFromEnv({ OPENROUTER_API_KEY: "k" })!.label, /via OpenRouter$/);
  assert.match(llmFromEnv({ NVIDIA_API_KEY: "k" })!.label, /^nvidia\/nemotron-3-super-120b-a12b via NVIDIA$/);
  assert.match(llmFromEnv({ NVIDIA_API_KEY: "k", LLM_MODEL: "z-ai/glm-5.3" })!.label, /^z-ai\/glm-5.3 via NVIDIA$/);
  assert.match(llmFromEnv({ LLM_PROVIDER: "openai", LLM_BASE_URL: "http://localhost:11434/v1", LLM_MODEL: "qwen3" })!.label, /qwen3 via localhost/);
  assert.match(llmFromEnv({ ANTHROPIC_API_KEY: "k" })!.label, /via Anthropic$/);
});

test("OpenAI-compatible: retries a 200 with an error body and a 429, then parses calls without ids", async () => {
  const replies = [
    json({ error: { message: "upstream provider overloaded" } }),
    json({ error: "rate limited" }, 429, { "retry-after": "0" }),
    json({
      choices: [
        {
          finish_reason: "tool_calls",
          message: { content: "<think>plan</think>", reasoning_details: [{ type: "reasoning.text", text: "plan" }], tool_calls: [{ function: { name: "explain_package", arguments: { name: "chalk" } } }] },
        },
      ],
    }),
  ];
  let calls = 0;
  const llm = openAiCompatible({ base: "http://x/v1", apiKey: "k", model: "m", name: "Test", fetchImpl: (async () => replies[calls++]) as typeof fetch });
  const r = await llm.chat([{ role: "user", content: "hi" }], []);
  assert.equal(calls, 3);
  assert.equal(r.text, "");
  assert.equal(r.calls.length, 1);
  assert.equal(r.calls[0].name, "explain_package");
  assert.deepEqual(r.calls[0].args, { name: "chalk" });
  assert.ok(r.calls[0].id, "a missing call id is filled in");
  assert.ok((r.message as any).reasoning_details, "OpenRouter reasoning is kept for the next turn");
});

test("OpenAI-compatible: a 401 fails at once, a cut-off answer is marked", async () => {
  let n = 0;
  const denied = openAiCompatible({ base: "http://x/v1", apiKey: "k", model: "m", name: "Test", fetchImpl: (async () => (n++, json({ error: "bad key" }, 401))) as typeof fetch });
  await assert.rejects(denied.chat([{ role: "user", content: "hi" }], []), /401/);
  assert.equal(n, 1);
  const cut = openAiCompatible({ base: "http://x/v1", apiKey: "", model: "m", name: "Test", fetchImpl: (async () => json({ choices: [{ finish_reason: "length", message: { content: "chalk@5.6.1 is" } }] })) as typeof fetch });
  assert.equal((await cut.chat([{ role: "user", content: "hi" }], [])).truncated, true);
});

test("answers may only name what the tools returned", () => {
  const corpus = '{"package":"chalk@5.6.1","route":"your project → lint-staged@16.1.6 → chalk@5.6.1","fixedIn":"5.6.2"}';
  assert.deepEqual(validate("chalk@5.6.1 arrives through lint-staged@16.1.6.", corpus), { ok: true, missing: [] });
  const bad = validate("chalk@5.6.1 and debug@4.4.2 are malware; also check `event-stream`.", corpus);
  assert.equal(bad.ok, false);
  assert.deepEqual(bad.missing.sort(), ["debug@4.4.2", "event-stream"]);
});

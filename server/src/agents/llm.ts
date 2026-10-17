import Anthropic from "@anthropic-ai/sdk";

// One small interface over OpenAI-compatible chat APIs (OpenRouter, NVIDIA NIM, Ollama, vLLM...) and Anthropic.
// The Analyst keeps its history in the OpenAI shape; the Anthropic adapter converts it on the way out.

export interface ToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>; // JSON Schema
}
export interface ToolCall {
  id: string;
  name: string;
  args: Record<string, unknown>;
}
export type Msg =
  | { role: "system" | "user"; content: string }
  | { role: "assistant"; content: string | null; tool_calls?: { id: string; type: "function"; function: { name: string; arguments: string }; [extra: string]: unknown }[]; [extra: string]: unknown }
  | { role: "tool"; tool_call_id: string; content: string };
export interface Reply {
  text: string;
  calls: ToolCall[];
  truncated: boolean;
  message: Msg; // the assistant message to append to the history as-is
}
export interface Llm {
  label: string; // "<model> via <provider>"
  chat(messages: Msg[], tools: ToolSpec[]): Promise<Reply>;
}

const PROVIDERS: Record<string, { base: string; key: string; model: string; name: string }> = {
  gemini: { base: "https://generativelanguage.googleapis.com/v1beta/openai", key: "GEMINI_API_KEY", model: "gemini-3.5-flash", name: "Gemini" },
  openrouter: { base: "https://openrouter.ai/api/v1", key: "OPENROUTER_API_KEY", model: "openai/gpt-oss-120b", name: "OpenRouter" },
  nvidia: { base: "https://integrate.api.nvidia.com/v1", key: "NVIDIA_API_KEY", model: "nvidia/nemotron-3-super-120b-a12b", name: "NVIDIA" },
};

/** The configured model, or null: then the built-in investigator answers. */
export function llmFromEnv(env = process.env): Llm | null {
  const model = env.LLM_MODEL?.trim();
  const pick = env.LLM_PROVIDER?.trim().toLowerCase();
  if (pick === "openai" || (!pick && env.LLM_BASE_URL)) {
    if (!env.LLM_BASE_URL) return null;
    return openAiCompatible({ base: env.LLM_BASE_URL, apiKey: env.LLM_API_KEY ?? "", model: model || "gpt-4o-mini", name: new URL(env.LLM_BASE_URL).hostname });
  }
  for (const id of pick ? [pick] : ["gemini", "openrouter", "nvidia"]) {
    const p = PROVIDERS[id];
    if (p && env[p.key]) return openAiCompatible({ base: p.base, apiKey: env[p.key]!, model: model || p.model, name: p.name });
  }
  if ((!pick || pick === "anthropic") && env.ANTHROPIC_API_KEY) return anthropic(env.ANTHROPIC_API_KEY, model || "claude-sonnet-5-5");
  return null;
}

/** Reasoning models put their thoughts in the content; the user only sees the answer. */
export const stripThinking = (s: string) =>
  s
    .replace(/[\u2010\u2011]/g, "-") // models like non-breaking hyphens; package names use plain ones
    .replace(/<(think|thinking|reasoning)>[\s\S]*?<\/\1>/gi, "")
    .replace(/^[\s\S]*?<\/(think|thinking)>/i, "")
    .trim();

/** Arguments arrive as a JSON string, an object, or broken JSON. Never throw on them. */
export function parseArgs(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === "object" && !Array.isArray(raw)) return raw as Record<string, unknown>;
  if (typeof raw !== "string" || !raw.trim()) return {};
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? v : {};
  } catch {
    const m = raw.match(/\{[\s\S]*\}/);
    try {
      return m ? JSON.parse(m[0]) : {};
    } catch {
      return {};
    }
  }
}

const extras = (c: any) => Object.fromEntries(Object.entries(c ?? {}).filter(([k]) => !["id", "type", "function", "index"].includes(k)));
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
class Retryable extends Error {
  constructor(message: string, readonly wait = 0) {
    super(message);
  }
}

/** Up to 3 attempts for rate limits, 5xx, network failures and 200 responses that carry an error body. */
async function withRetry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  for (let i = 1; ; i++) {
    try {
      return await fn();
    } catch (e: any) {
      // A model that timed out once will usually time out again: fail over to the built-in investigator instead.
      const timedOut = e?.name === "TimeoutError";
      const retry = e instanceof Retryable || e?.cause?.code || e?.name === "TypeError";
      if (timedOut || !retry || i >= attempts) throw e instanceof Retryable ? new Error(e.message) : e;
      await sleep(Math.min(20_000, (e as Retryable).wait || 1000 * 2 ** (i - 1)));
    }
  }
}

export function openAiCompatible(o: { base: string; apiKey: string; model: string; name: string; fetchImpl?: typeof fetch }): Llm {
  const f = o.fetchImpl ?? fetch;
  const url = `${o.base.replace(/\/$/, "")}/chat/completions`;
  return {
    label: `${o.model} via ${o.name}`,
    async chat(messages, tools) {
      const data: any = await withRetry(async () => {
        const res = await f(url, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            ...(o.apiKey ? { authorization: `Bearer ${o.apiKey}` } : {}),
            "x-title": "Taintgraph",
            "http-referer": "https://github.com/kalash33/taintgraph",
          },
          body: JSON.stringify({
            model: o.model,
            messages,
            tools: tools.map((t) => ({ type: "function", function: t })),
            tool_choice: "auto",
            temperature: 0,
            max_tokens: 2000,
          }),
          signal: AbortSignal.timeout(45_000),
        });
        const body = await res.text();
        if (res.status === 429 || res.status >= 500) throw new Retryable(`${o.name} ${res.status}: ${body.slice(0, 200)}`, Number(res.headers.get("retry-after")) * 1000 || 0);
        if (!res.ok) throw new Error(`${o.name} ${res.status}: ${body.slice(0, 300)}`);
        let json: any;
        try {
          json = JSON.parse(body);
        } catch {
          throw new Retryable(`${o.name} returned something that isn't JSON`);
        }
        // OpenRouter reports upstream failures as 200 with an error body.
        if (json.error) throw new Retryable(`${o.name}: ${json.error.message ?? JSON.stringify(json.error).slice(0, 200)}`);
        if (!json.choices?.length) throw new Retryable(`${o.name} returned no choices`);
        return json;
      });
      const choice = data.choices[0];
      const msg = choice.message ?? {};
      const raw = (msg.tool_calls ?? []).filter((c: any) => c?.function?.name);
      const calls: ToolCall[] = raw.map((c: any, i: number) => ({ id: c.id || `call_${Date.now().toString(36)}_${i}`, name: c.function.name, args: parseArgs(c.function.arguments) }));
      const text = stripThinking(typeof msg.content === "string" ? msg.content : "");
      const message: Msg = {
        role: "assistant",
        content: text || null,
        // Provider extras on each call (Gemini's thought signatures) must go back unchanged on the next turn.
        ...(calls.length ? { tool_calls: calls.map((c, i) => ({ ...extras(raw[i]), id: c.id, type: "function" as const, function: { name: c.name, arguments: JSON.stringify(c.args) } })) } : {}),
        // OpenRouter asks for reasoning to be sent back unchanged so reasoning models keep their chain across tool calls.
        ...(msg.reasoning_details ? { reasoning_details: msg.reasoning_details } : {}),
      };
      return { text, calls, truncated: choice.finish_reason === "length", message };
    },
  };
}

export function anthropic(apiKey: string, model: string): Llm {
  const client = new Anthropic({ apiKey, maxRetries: 3, timeout: 90_000 });
  return {
    label: `${model} via Anthropic`,
    async chat(messages, tools) {
      const system = messages.filter((m) => m.role === "system").map((m) => m.content as string).join("\n\n");
      const out: Anthropic.MessageParam[] = [];
      for (const m of messages) {
        if (m.role === "user") out.push({ role: "user", content: m.content });
        else if (m.role === "assistant") {
          const blocks: Anthropic.ContentBlockParam[] = [];
          if (m.content) blocks.push({ type: "text", text: m.content });
          for (const c of m.tool_calls ?? []) blocks.push({ type: "tool_use", id: c.id, name: c.function.name, input: parseArgs(c.function.arguments) });
          if (blocks.length) out.push({ role: "assistant", content: blocks });
        } else if (m.role === "tool") {
          const block: Anthropic.ToolResultBlockParam = { type: "tool_result", tool_use_id: m.tool_call_id, content: m.content };
          const last = out[out.length - 1];
          // Consecutive tool results belong in one user turn.
          if (last?.role === "user" && Array.isArray(last.content) && last.content.every((b) => b.type === "tool_result")) (last.content as Anthropic.ToolResultBlockParam[]).push(block);
          else out.push({ role: "user", content: [block] });
        }
      }
      const res = await client.messages.create({
        model,
        max_tokens: 2000,
        system,
        messages: out,
        tools: tools.map((t) => ({ name: t.name, description: t.description, input_schema: t.parameters as Anthropic.Tool.InputSchema })),
      });
      const text = stripThinking(res.content.flatMap((b) => (b.type === "text" ? [b.text] : [])).join("\n"));
      const calls = res.content.flatMap((b) => (b.type === "tool_use" ? [{ id: b.id, name: b.name, args: parseArgs(b.input) }] : []));
      return {
        text,
        calls,
        truncated: res.stop_reason === "max_tokens",
        message: { role: "assistant", content: text || null, ...(calls.length ? { tool_calls: calls.map((c) => ({ id: c.id, type: "function" as const, function: { name: c.name, arguments: JSON.stringify(c.args) } })) } : {}) },
      };
    },
  };
}

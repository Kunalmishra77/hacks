import type { AiProvider } from "./advice.js";

// Two interchangeable LLM providers behind the AiProvider interface. The
// product's operator picks one; the advisory logic doesn't care which.

export interface ProviderConfig {
  provider: "anthropic" | "openai";
  apiKey: string;
  model?: string;
}

/** Anthropic via the official SDK (default model claude-opus-5-5). */
export function createAnthropicProvider(apiKey: string, model = "claude-opus-5-5"): AiProvider {
  return {
    name: "anthropic",
    model,
    async complete({ system, user, maxTokens = 1024 }) {
      // Lazy import so the SDK is only needed when Anthropic is the chosen provider.
      const { default: Anthropic } = await import("@anthropic-ai/sdk");
      const client = new Anthropic({ apiKey });
      const res = await client.messages.create({
        model,
        max_tokens: maxTokens,
        system,
        messages: [{ role: "user", content: user }],
      });
      return res.content
        .map((b) => (b.type === "text" ? b.text : ""))
        .filter(Boolean)
        .join("\n");
    },
  };
}

/** OpenAI Chat Completions via fetch (no SDK dependency). */
export function createOpenAiProvider(apiKey: string, model = "gpt-4o-mini", fetchFn: typeof fetch = fetch): AiProvider {
  return {
    name: "openai",
    model,
    async complete({ system, user, maxTokens = 1024 }) {
      const res = await fetchFn("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { authorization: `Bearer ${apiKey}`, "content-type": "application/json" },
        body: JSON.stringify({
          model,
          max_tokens: maxTokens,
          temperature: 0.2,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
        }),
        signal: AbortSignal.timeout(60_000),
      });
      if (!res.ok) throw new Error(`OpenAI HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
      const body = (await res.json()) as { choices?: { message?: { content?: string } }[] };
      return body.choices?.[0]?.message?.content ?? "";
    },
  };
}

export function createProvider(config: ProviderConfig): AiProvider {
  if (config.provider === "anthropic") return createAnthropicProvider(config.apiKey, config.model);
  return createOpenAiProvider(config.apiKey, config.model);
}

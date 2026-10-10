import { describe, expect, it } from "vitest";
import { runTool, ToolMissingError } from "../src/exec.js";

const node = process.execPath;

describe("runTool", () => {
  it("passes stdin and returns stdout", async () => {
    const r = await runTool({ bin: node, args: ["-e", "process.stdin.pipe(process.stdout)"], input: "a.example.com\n", timeoutMs: 10_000 });
    expect(r).toMatchObject({ stdout: "a.example.com\n", exitCode: 0, truncated: false });
  });

  it("never uses a shell: metacharacters in args are inert", async () => {
    const r = await runTool({
      bin: node,
      args: ["-e", "console.log(process.argv[1])", "example.com; echo pwned && rm -rf /"],
      timeoutMs: 10_000,
    });
    expect(r.stdout.trim()).toBe("example.com; echo pwned && rm -rf /");
  });

  it("does not leak platform secrets into the tool's environment", async () => {
    process.env.AEGIS_TEST_SECRET = "s3cret";
    try {
      const r = await runTool({ bin: node, args: ["-e", "console.log(process.env.AEGIS_TEST_SECRET ?? 'none')"], timeoutMs: 10_000 });
      expect(r.stdout.trim()).toBe("none");
    } finally {
      delete process.env.AEGIS_TEST_SECRET;
    }
  });

  it("kills the tool on timeout and on abort", async () => {
    await expect(runTool({ bin: node, args: ["-e", "setTimeout(()=>{}, 60000)"], timeoutMs: 200 })).rejects.toThrow(/timed out/);

    const ac = new AbortController();
    const p = runTool({ bin: node, args: ["-e", "setTimeout(()=>{}, 60000)"], timeoutMs: 60_000, signal: ac.signal });
    setTimeout(() => ac.abort(new Error("killed by kill-switch")), 100);
    await expect(p).rejects.toThrow("killed by kill-switch");
  });

  it("caps output size", async () => {
    const r = await runTool({
      bin: node,
      args: ["-e", "for(let i=0;i<1e5;i++) process.stdout.write('x'.repeat(100))"],
      timeoutMs: 20_000,
      maxOutputBytes: 10_000,
    });
    expect(r.truncated).toBe(true);
    expect(r.stdout.length).toBeLessThanOrEqual(10_000);
  });

  it("reports a missing binary clearly", async () => {
    await expect(runTool({ bin: "aegis-no-such-tool", args: [], timeoutMs: 5_000 })).rejects.toBeInstanceOf(ToolMissingError);
  });
});

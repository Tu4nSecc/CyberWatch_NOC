/**
 * React hook example for the SOC Lynis SSE endpoint.
 * Copy into a Next.js/React app; point `apiBase` at your Flask server (e.g. http://172.25.0.10:5000).
 *
 * Usage:
 *   const { logs, result, scanning, error, startScan } = useLynisScan({ apiBase: '' });
 *   startScan({ target_ip, user, ssh_pass, sudo_pass });
 */
import { useCallback, useRef, useState } from "react";

export type LynisScanInput = {
  target_ip: string;
  user: string;
  ssh_pass: string;
  sudo_pass: string;
  port?: number;
};

export type LynisFinding = {
  severity: string;
  category: string;
  finding: string;
  remediation: string;
};

export type LynisCompletePayload = {
  ok: boolean;
  stats: {
    hardening_index: number | null;
    warnings: number;
    suggestions: number;
  };
  findings: LynisFinding[];
  error?: string | null;
};

function parseSSEBlocks(buffer: string): { rest: string; blocks: string[] } {
  const blocks: string[] = [];
  let rest = buffer;
  let sep: number;
  while ((sep = rest.indexOf("\n\n")) >= 0) {
    blocks.push(rest.slice(0, sep).trim());
    rest = rest.slice(sep + 2);
  }
  return { rest, blocks };
}

function parseBlock(block: string): { event: string; data: string } {
  let event = "message";
  const dataLines: string[] = [];
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataLines.push(line.slice(5).trim());
  }
  return { event, data: dataLines.join("\n") };
}

export function useLynisScan(options: { apiBase?: string } = {}) {
  const apiBase = options.apiBase ?? "";
  const [logs, setLogs] = useState<string[]>([]);
  const [result, setResult] = useState<LynisCompletePayload | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const abortRef = useRef<AbortController | null>(null);

  const startScan = useCallback(
    async (input: LynisScanInput) => {
      abortRef.current?.abort();
      const ac = new AbortController();
      abortRef.current = ac;
      setScanning(true);
      setError(null);
      setResult(null);
      setLogs([]);

      try {
        const res = await fetch(`${apiBase}/api/lynis/scan`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(input),
          signal: ac.signal,
        });
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}`);
        }
        const reader = res.body?.getReader();
        if (!reader) throw new Error("No response body");
        const dec = new TextDecoder();
        let buf = "";
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const { rest, blocks } = parseSSEBlocks(buf);
          buf = rest;
          for (const block of blocks) {
            if (!block) continue;
            const { event, data } = parseBlock(block);
            if (event === "complete" && data) {
              const payload = JSON.parse(data) as LynisCompletePayload;
              setResult(payload);
            } else if (data) {
              const o = JSON.parse(data) as { type?: string; line?: string; message?: string };
              if (o.type === "log" && o.line) setLogs((L) => [...L, o.line!]);
              if (o.type === "error") setLogs((L) => [...L, `[ERROR] ${o.message ?? ""}`]);
            }
          }
        }
      } catch (e: unknown) {
        if ((e as Error).name === "AbortError") return;
        setError((e as Error).message || String(e));
      } finally {
        setScanning(false);
      }
    },
    [apiBase]
  );

  const cancel = useCallback(() => abortRef.current?.abort(), []);

  return { logs, result, scanning, error, startScan, cancel };
}

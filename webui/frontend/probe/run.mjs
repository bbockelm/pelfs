#!/usr/bin/env node
// Starts the logging stub on an ephemeral port, runs the given probe script
// against it, and shuts the stub down. No fixed ports, no leftover
// processes, no sleeps: the child is started and the parent waits for the
// line the stub prints when it is actually listening.
import { spawn } from "node:child_process";
import { once } from "node:events";
import net from "node:net";

const script = process.argv[2];
if (!script) {
  console.error("usage: node probe/run.mjs <probe script>");
  process.exit(2);
}

// An ephemeral port chosen by the OS, then handed to both halves.
const probe = net.createServer();
probe.listen(0, "127.0.0.1");
await once(probe, "listening");
const port = probe.address().port;
await new Promise((r) => probe.close(r));

const stub = spawn(process.execPath, ["probe/stub.mjs"], {
  env: { ...process.env, PORT: String(port) },
  stdio: ["ignore", "pipe", "inherit"],
});
await new Promise((resolve, reject) => {
  stub.stdout.on("data", (b) => {
    process.stdout.write(b);
    if (String(b).includes("listening")) resolve();
  });
  stub.once("exit", (c) => reject(new Error(`stub exited with ${c} before listening`)));
});

const child = spawn(process.execPath, [script], {
  env: { ...process.env, PORT: String(port) },
  stdio: "inherit",
});
const [code] = await once(child, "exit");
stub.kill("SIGTERM");
process.exit(code ?? 1);

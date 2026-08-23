#!/usr/bin/env node
// The logging stub the U0 probe runs against: it speaks the SVAR REST
// contract, answers with synthetic trees, and records every request --
// method, path exactly as sent (percent-encoding preserved), query,
// content-type and body.
//
// It is a stub, not a design: the real thing is work item U11, and the point
// of this file is to find out what U11 will be answering BEFORE it is
// written.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const web = process.env.PROBE_WEB || path.join(here, "..", ".probe-dist");

const log = [];
let scenario = "lazy";
let big = Number(process.env.PROBE_BIG || 100000);

function lazyListing(prefix, deeper) {
  const out = [];
  for (let i = 0; i < 3; i++)
    out.push({ id: `${prefix}dir-${i}`, type: "folder", lazy: deeper, date: "2026-08-23T12:00:00Z" });
  for (let i = 0; i < 5; i++)
    out.push({ id: `${prefix}file-${i}.txt`, type: "file", size: 1024 * (i + 1), date: "2026-08-23T12:00:00Z" });
  return out;
}

function listing(id) {
  const prefix = id === "/" || id === "" ? "/" : `${id}/`;
  if (scenario === "big") {
    if (prefix === "/") return [{ id: "/big", type: "folder", lazy: true }];
    const out = new Array(big);
    for (let i = 0; i < big; i++) out[i] = { id: `${prefix}f${i}.dat`, type: "file", size: i };
    return out;
  }
  const depth = prefix === "/" ? 0 : prefix.split("/").filter(Boolean).length;
  return lazyListing(prefix, depth < 3);
}

const mime = {
  ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".svg": "image/svg+xml",
  ".png": "image/png", ".ico": "image/x-icon", ".woff": "font/woff", ".woff2": "font/woff2",
};

const srv = http.createServer((req, res) => {
  const body = [];
  req.on("data", (c) => body.push(c));
  req.on("end", () => {
    const u = new URL(req.url, "http://127.0.0.1");
    const p = u.pathname;
    const raw = Buffer.concat(body);
    const multipart = /multipart/.test(req.headers["content-type"] || "");
    let rec = null;
    if (p.startsWith("/api/")) {
      rec = {
        method: req.method,
        path: p, // percent-encoding preserved exactly as the component sent it
        query: u.search || "",
        contentType: req.headers["content-type"] ?? null,
        sessionHeader: req.headers["x-pelfs-session"] ?? null,
        bodyBytes: raw.length,
        body: !raw.length ? null : multipart ? `<multipart, ${raw.length} bytes>` : raw.toString("utf8").slice(0, 2048),
      };
      log.push(rec);
    }
    const json = (v) => {
      if (rec) rec.status = 200;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(v));
    };

    if (p === "/__log") return json(log);
    if (p === "/__reset") {
      log.length = 0;
      scenario = u.searchParams.get("scenario") || "lazy";
      if (u.searchParams.get("size")) big = Number(u.searchParams.get("size"));
      return json({ ok: true, scenario, size: big });
    }
    // The Host header, echoed. This is what makes Chromium's
    // --host-resolver-rules provably a DNS-rebinding simulation rather than a
    // flag somebody passed: the page's own requests must arrive claiming the
    // attacker's hostname. internal/httpguard is what will answer 421 to it.
    if (p === "/__host") return json({ host: req.headers.host ?? null });

    if (req.method === "GET" && p === "/api/v1/files") return json(listing("/"));
    if (req.method === "GET" && p.startsWith("/api/v1/files/"))
      return json(listing(decodeURIComponent(p.slice("/api/v1/files/".length))));
    if (p === "/api/v1/info" || p.startsWith("/api/v1/info/"))
      return json({ used: 1 << 30, total: 1 << 34, volume: "pelican://demo.example/prefix", mode: "read-only" });

    if (req.method === "POST" && p.startsWith("/api/v1/files/")) {
      const parent = decodeURIComponent(p.slice("/api/v1/files/".length));
      const b = JSON.parse(raw.toString() || "{}");
      return json({ result: { id: `${parent === "/" ? "" : parent}/${b.name}`, type: b.type } });
    }
    if (req.method === "POST" && p === "/api/v1/upload") {
      const parent = decodeURIComponent(u.searchParams.get("id") || "/");
      return json({ result: { id: `${parent === "/" ? "" : parent}/uploaded.bin`, size: raw.length } });
    }
    if (req.method === "PUT" && p.startsWith("/api/v1/files/")) {
      const id = decodeURIComponent(p.slice("/api/v1/files/".length));
      const b = JSON.parse(raw.toString() || "{}");
      const parent = id.slice(0, id.lastIndexOf("/")) || "/";
      return json({ result: { id: `${parent === "/" ? "" : parent}/${b.name}` } });
    }
    if (req.method === "PUT" && p === "/api/v1/files") {
      const b = JSON.parse(raw.toString() || "{}");
      return json({
        result: b.ids.map((i) => ({ id: `${b.target === "/" ? "" : b.target}${i.slice(i.lastIndexOf("/"))}` })),
      });
    }
    if (req.method === "DELETE" && p === "/api/v1/files") return json({ result: true });

    const file = path.join(web, p === "/" ? "/index.html" : p);
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      res.writeHead(200, { "Content-Type": mime[path.extname(file)] || "application/octet-stream" });
      return res.end(fs.readFileSync(file));
    }
    res.writeHead(404);
    res.end("not found\n");
  });
});

srv.listen(Number(process.env.PORT || 8781), "127.0.0.1", () => {
  const { port } = srv.address();
  console.log(`probe stub listening on http://127.0.0.1:${port} serving ${web}`);
});

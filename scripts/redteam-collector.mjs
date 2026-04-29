#!/usr/bin/env node
import http from "node:http";

const port = Number(process.env.PORT || 8787);

const server = http.createServer(async (req, res) => {
  const chunks = [];
  req.on("data", (c) => chunks.push(c));
  req.on("end", () => {
    const body = Buffer.concat(chunks).toString("utf-8");
    const line = [
      new Date().toISOString(),
      req.method,
      req.url,
      `len=${body.length}`,
      body.slice(0, 200).replace(/\n/g, "\\n"),
    ].join(" | ");
    console.log(line);
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end("ok");
  });
});

// Bind to all interfaces. In Node.js this typically binds to IPv6 '::' and
// also accepts IPv4 via dual-stack when available, avoiding localhost(::1) issues.
server.listen(port, () => {
  console.log(`redteam collector listening on http://localhost:${port}/collect`);
});


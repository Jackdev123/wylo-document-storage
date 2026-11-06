import { createServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { readFile } from "node:fs/promises";
import { extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || "127.0.0.1";
const allowedFiles = new Set(["index.html", "styles.css", "app.js"]);
const contentTypes = { ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8" };

const handleRequest = async (request, response) => {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { "Content-Type": "text/plain; charset=utf-8", "Allow": "GET, HEAD", "Cache-Control": "no-store" });
    response.end("Method not allowed");
    return;
  }

  let requested;
  try {
    const url = new URL(request.url || "/", "http://localhost");
    requested = url.pathname === "/" ? "index.html" : decodeURIComponent(url.pathname.slice(1));
  } catch {
    response.writeHead(400, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Bad request");
    return;
  }
  if (!allowedFiles.has(requested) || requested.includes(sep) || requested.includes("..")) {
    response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Not found");
    return;
  }

  try {
    const path = resolve(root, requested);
    const body = await readFile(path);
    response.writeHead(200, {
      "Content-Type": contentTypes[extname(path)],
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob: data:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    });
    response.end(request.method === "HEAD" ? undefined : body);
  } catch (error) {
    if (error.code === "ENOENT") {
      response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
      response.end("Not found");
      return;
    }
    console.error("WDS could not serve a local application file:", error.message);
    response.writeHead(500, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" });
    response.end("Could not serve the application file");
  }
};

const certFile = process.env.TLS_CERT_FILE;
const keyFile = process.env.TLS_KEY_FILE;
if (Boolean(certFile) !== Boolean(keyFile)) {
  throw new Error("Set both TLS_CERT_FILE and TLS_KEY_FILE to enable HTTPS.");
}

const server = certFile
  ? createHttpsServer({ cert: await readFile(certFile), key: await readFile(keyFile) }, handleRequest)
  : createServer(handleRequest);

server.on("error", error => {
  console.error("WDS local server failed:", error.message);
  process.exitCode = 1;
});

server.listen(port, host, () => {
  const displayHost = host === "0.0.0.0" ? "127.0.0.1" : host;
  console.log(`WDS is running at ${certFile ? "https" : "http"}://${displayHost}:${port}`);
  console.log("This server serves the app only; vault data stays in your browser.");
});

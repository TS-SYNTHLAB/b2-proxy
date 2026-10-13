import { existsSync, readFileSync } from "node:fs";
import { Readable } from "node:stream";
import { ReadableStream as WebReadableStream } from "node:stream/web";
import Fastify, { type FastifyReply, type FastifyRequest } from "fastify";
import { resolveConfig } from "./config.js";
import { handleProxy, type ProxyInput } from "./proxy.js";
import { checkB2Credentials, warnOnSuspiciousCredentials } from "./validate.js";

function loadEnvFile(path: string): void {
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split("\n")) {
    const match = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
    if (match && process.env[match[1]] === undefined) {
      process.env[match[1]] = match[2].replace(/^(['"])(.*)\1$/, "$2");
    }
  }
}

loadEnvFile(".env");

const config = resolveConfig(process.env);
warnOnSuspiciousCredentials(config, (message) => process.stderr.write(`[b2-proxy] AVISO: ${message}\n`));
for (const warning of await checkB2Credentials(config)) {
  process.stderr.write(`[b2-proxy] AVISO: ${warning}\n`);
}

const SKIP_RESPONSE_HEADERS = new Set([
  "connection",
  "keep-alive",
  "transfer-encoding",
  "te",
  "trailer",
  "upgrade",
  "set-cookie",
]);

const METHODS = ["GET", "HEAD", "PUT", "POST", "DELETE", "PATCH", "OPTIONS"] as const;

const encoder = new TextEncoder();

function toBodyBytes(body: unknown): Uint8Array<ArrayBuffer> | null {
  if (body === undefined || body === null) return null;
  if (Buffer.isBuffer(body)) return new Uint8Array(body);
  if (body instanceof Uint8Array) return new Uint8Array(body);
  if (typeof body === "string") return new Uint8Array(encoder.encode(body));
  return new Uint8Array(encoder.encode(JSON.stringify(body)));
}

async function proxyHandler(request: FastifyRequest, reply: FastifyReply): Promise<FastifyReply> {
  const rawUrl = request.raw.url ?? "/";
  const queryIndex = rawUrl.indexOf("?");

  const headers: [string, string][] = [];
  for (const [name, value] of Object.entries(request.headers)) {
    if (Array.isArray(value)) {
      for (const item of value) headers.push([name, item]);
    } else if (value !== undefined) {
      headers.push([name, value]);
    }
  }

  const hasBody = request.method !== "GET" && request.method !== "HEAD";
  const input: ProxyInput = {
    method: request.method,
    path: queryIndex === -1 ? rawUrl : rawUrl.slice(0, queryIndex),
    rawQuery: queryIndex === -1 ? "" : rawUrl.slice(queryIndex + 1),
    headers,
    body: hasBody ? toBodyBytes(request.body) : null,
  };

  try {
    const response = await handleProxy(input, config, (message) => request.log.warn(message));

    reply.code(response.status);
    reply.header("x-b2-proxy", "1");
    for (const [name, value] of response.headers.entries()) {
      if (!SKIP_RESPONSE_HEADERS.has(name)) reply.header(name, value);
    }
    const setCookies = response.headers.getSetCookie();
    if (setCookies.length > 0) reply.header("set-cookie", setCookies);

    if (request.method === "HEAD" || response.body === null) {
      return reply.send();
    }
    return reply.send(Readable.fromWeb(response.body as unknown as WebReadableStream<Uint8Array>));
  } catch (error) {
    request.log.error(error);
    const message = error instanceof Error ? error.message : String(error);
    return reply.code(502).header("x-b2-proxy", "1").send({ error: "b2-proxy", message });
  }
}

const fastify = Fastify({
  logger: true,
  requestTimeout: 0,
  bodyLimit: Number(process.env.BODY_LIMIT ?? 512 * 1024 * 1024),
});

fastify.addContentTypeParser("*", { parseAs: "buffer" }, (_request, body, done) => {
  done(null, body);
});

for (const url of ["/", "/*"] as const) {
  fastify.route({ method: [...METHODS], url, handler: proxyHandler });
}

const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "0.0.0.0";

fastify.listen({ port, host }).catch((error) => {
  fastify.log.error(error);
  process.exit(1);
});

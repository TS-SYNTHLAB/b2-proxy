import type { Config } from "./config.js";
import {
  collectClientHeaders,
  parseClientAuthorization,
  PresignError,
  stripAmzQueryParams,
  verifyClientAuthorization,
  verifyPresignedRequest,
  type ClientAuth,
} from "./auth.js";
import { findHeader, UNSIGNED_PAYLOAD } from "./headers.js";
import { isPresigned, parseRawQuery } from "./query.js";
import { EMPTY_PAYLOAD_HASH, sha256Hex, signRequest, toAmzDate } from "./sign.js";
import { buildUpstreamUrl, forwardToUpstream } from "./upstream.js";

const SIGNABLE_HEADERS = new Set([
  "cache-control",
  "content-type",
  "expires",
  "if-match",
  "if-modified-since",
  "if-none-match",
  "if-unmodified-since",
  "range",
]);

export interface ProxyInput {
  method: string;
  path: string;
  rawQuery: string;
  headers: [string, string][];
  body: Uint8Array<ArrayBuffer> | null;
}

export type ProxyLogger = (message: string) => void;

const noop: ProxyLogger = () => {};

function tagResponse(response: Response): Response {
  const tagged = new Response(response.body, response);
  tagged.headers.set("x-b2-proxy", "1");
  return tagged;
}

function errorResponse(status: number, code: string, message?: string): Response {
  return new Response(
    `<?xml version="1.0" encoding="UTF-8"?><Error><Code>${code}</Code><Message>${message ?? code}</Message></Error>`,
    { status, headers: { "content-type": "application/xml", "x-b2-proxy": "1" } },
  );
}

async function authorizeClient(
  input: ProxyInput,
  upstreamHost: string,
  client: ClientAuth,
  log: ProxyLogger,
): Promise<Response | null> {
  const authHeader = findHeader(input.headers, "authorization");
  if (authHeader === undefined) {
    log("client auth rejected: missing Authorization header");
    return errorResponse(403, "AccessDenied");
  }
  const credentials = parseClientAuthorization(authHeader);
  if (credentials === null) {
    log("client auth rejected: malformed Authorization header");
    return errorResponse(400, "AuthorizationHeaderMalformed");
  }
  try {
    const valid = await verifyClientAuthorization(
      {
        method: input.method,
        path: input.path,
        rawQuery: input.rawQuery,
        headers: input.headers,
        clientHost: findHeader(input.headers, "host"),
        upstreamHost,
      },
      authHeader,
      credentials,
      client,
    );
    if (!valid) {
      log("client auth rejected: signature mismatch (wrong secret or non-standard signer)");
      return errorResponse(403, "SignatureDoesNotMatch");
    }
    return null;
  } catch (error) {
    if (error instanceof PresignError) {
      log(`client auth rejected: ${error.message}`);
      return errorResponse(403, error.code, error.clientMessage);
    }
    throw error;
  }
}

export async function handleProxy(
  input: ProxyInput,
  config: Config,
  log: ProxyLogger = noop,
): Promise<Response> {
  const upstreamHost = new URL(config.upstream).host;
  const requestHost = findHeader(input.headers, "host");
  if (requestHost !== undefined && requestHost === upstreamHost) {
    throw new Error(`UPSTREAM_URL (${config.upstream}) points to the proxy's own host (${requestHost})`);
  }

  const clientHeaders = collectClientHeaders(input.headers);
  const presigned = isPresigned(parseRawQuery(input.rawQuery));
  const clientAuth: ClientAuth | undefined =
    config.clientKeyId !== undefined && config.clientSecret !== undefined
      ? { keyId: config.clientKeyId, secret: config.clientSecret }
      : undefined;

  let rawQuery = input.rawQuery;

  if (presigned) {
    if (clientAuth !== undefined) {
      try {
        const verified = await verifyPresignedRequest(
          {
            method: input.method,
            path: input.path,
            rawQuery: input.rawQuery,
            headers: input.headers,
            clientHost: requestHost,
            upstreamHost,
          },
          clientAuth,
        );
        rawQuery = verified.cleanQuery;
      } catch (error) {
        if (error instanceof PresignError) {
          log(`presign verification rejected: ${error.message}`);
          return errorResponse(403, error.code, error.clientMessage);
        }
        throw error;
      }
    } else {
      rawQuery = stripAmzQueryParams(parseRawQuery(input.rawQuery));
    }
  } else if (clientAuth !== undefined) {
    const denied = await authorizeClient(input, upstreamHost, clientAuth, log);
    if (denied !== null) return denied;
  }

  const headers = clientHeaders.forwarded;

  const amzDate = toAmzDate(new Date());
  const payloadHash = input.body === null ? EMPTY_PAYLOAD_HASH : await sha256Hex(input.body);
  const signingHeaders: Record<string, string> = { host: upstreamHost };
  for (const [name, value] of Object.entries(headers)) {
    if (SIGNABLE_HEADERS.has(name)) signingHeaders[name] = value;
  }
  signingHeaders["x-amz-content-sha256"] = payloadHash;
  signingHeaders["x-amz-date"] = amzDate;

  headers["x-amz-content-sha256"] = payloadHash;
  headers["x-amz-date"] = amzDate;
  headers["authorization"] = await signRequest({
    method: input.method,
    path: input.path,
    rawQuery,
    headers: signingHeaders,
    payloadHash,
    keyId: config.keyId,
    appKey: config.appKey,
    region: config.region,
    amzDate,
  });

  const url = buildUpstreamUrl(config.upstream, input.path, rawQuery);
  return tagResponse(await forwardToUpstream(url, input.method, headers, input.body));
}

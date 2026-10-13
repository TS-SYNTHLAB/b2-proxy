import { deriveSigningKey, EMPTY_PAYLOAD_HASH, hmacHex, sha256Hex, signRequest } from "./sign.js";
import { canonicalizeQuery, parseRawQuery, type CanonicalQueryOptions } from "./query.js";

export interface ClientAuth {
  keyId: string;
  secret: string;
}

export interface ClientCredentials {
  keyId: string;
  dateStamp: string;
  region: string;
  signedHeaders: string[];
}

export interface ClientRequestHeaders {
  forwarded: Record<string, string>;
  amz: Record<string, string>;
}

export class PresignError extends Error {
  constructor(
    message: string,
    readonly code: string = "SignatureDoesNotMatch",
    readonly clientMessage: string = code,
  ) {
    super(message);
  }
}

const encoder = new TextEncoder();

function timingSafeEqual(a: string, b: string): boolean {
  const bufA = encoder.encode(a);
  const bufB = encoder.encode(b);
  if (bufA.length !== bufB.length) return false;
  let diff = 0;
  for (let i = 0; i < bufA.length; i++) diff |= bufA[i] ^ bufB[i];
  return diff === 0;
}

export function parseClientAuthorization(header: string): ClientCredentials | null {
  const trimmed = header.trim();
  if (!/^AWS4-HMAC-SHA256\s+/i.test(trimmed)) return null;
  const pairs = new Map<string, string>();
  for (const part of trimmed.slice("AWS4-HMAC-SHA256".length).split(",")) {
    const index = part.indexOf("=");
    if (index === -1) continue;
    pairs.set(part.slice(0, index).trim().toLowerCase(), part.slice(index + 1).trim());
  }
  const credential = pairs.get("credential");
  const signedHeaders = pairs.get("signedheaders");
  if (!credential || !signedHeaders) return null;
  const parts = credential.split("/");
  if (parts.length !== 5 || parts[3] !== "s3" || parts[4] !== "aws4_request") return null;
  const [keyId, dateStamp, region] = parts;
  if (keyId === undefined || dateStamp === undefined || region === undefined) return null;
  return {
    keyId,
    dateStamp,
    region,
    signedHeaders: signedHeaders.split(";").map((name) => name.trim().toLowerCase()).filter(Boolean),
  };
}

const BLOCKED_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "te",
  "trailer",
  "transfer-encoding",
  "upgrade",
  "host",
  "content-length",
  "content-md5",
  "authorization",
]);

export function collectClientHeaders(entries: Iterable<[string, string]>): ClientRequestHeaders {
  const forwarded: Record<string, string> = {};
  const amz: Record<string, string> = {};
  for (const [rawName, value] of entries) {
    const name = rawName.toLowerCase();
    if (BLOCKED_HEADERS.has(name)) continue;
    if (name.startsWith("cf-") || name.startsWith("cdn-")) continue;
    if (name.startsWith("x-amz-")) {
      amz[name] = value;
      continue;
    }
    forwarded[name] = value;
  }
  return { forwarded, amz };
}

function lookupSignedHeader(headers: [string, string][], name: string): string | undefined {
  for (const [rawName, value] of headers) {
    if (rawName.toLowerCase() === name) return value;
  }
  return undefined;
}

export interface VerifyHeaderInput {
  method: string;
  path: string;
  rawQuery: string;
  headers: [string, string][];
  clientHost?: string;
  upstreamHost: string;
}

export async function verifyClientAuthorization(
  input: VerifyHeaderInput,
  authHeader: string,
  credentials: ClientCredentials,
  client: ClientAuth,
): Promise<boolean> {
  if (!timingSafeEqual(credentials.keyId, client.keyId)) return false;

  const amzDate = lookupSignedHeader(input.headers, "x-amz-date");
  if (amzDate === undefined || !/^\d{8}T\d{6}Z$/.test(amzDate)) return false;
  if (credentials.dateStamp !== amzDate.slice(0, 8)) return false;

  const hostCandidates = [
    ...new Set([input.clientHost, input.upstreamHost].filter((v): v is string => v !== undefined)),
  ];

  let missingHeader: string | undefined;
  for (const host of hostCandidates) {
    const headersToSign: Record<string, string> = {};
    let missing = false;
    for (const name of credentials.signedHeaders) {
      if (name === "host") {
        headersToSign.host = host;
        continue;
      }
      const value = lookupSignedHeader(input.headers, name);
      if (value === undefined) {
        missing = true;
        missingHeader = name;
        break;
      }
      headersToSign[name] = value;
    }
    if (missing) continue;

    const expected = await signRequest({
      method: input.method,
      path: input.path,
      rawQuery: input.rawQuery,
      headers: headersToSign,
      payloadHash: headersToSign["x-amz-content-sha256"] ?? "UNSIGNED-PAYLOAD",
      keyId: credentials.keyId,
      appKey: client.secret,
      region: credentials.region,
      amzDate,
    });
    if (timingSafeEqual(expected, authHeader.trim())) return true;
  }
  if (missingHeader !== undefined) {
    throw new PresignError(
      `Signed header missing from request: ${missingHeader}`,
      "SignatureDoesNotMatch",
      `header '${missingHeader}' is listed in signed headers, but is not present`,
    );
  }
  return false;
}

const SIGNED_QUERY_PARAM = "X-Amz-Signature";
const MAX_PRESIGN_EXPIRES_SECONDS = 86400;

export interface VerifyPresignInput {
  method: string;
  path: string;
  rawQuery: string;
  headers: [string, string][];
  clientHost?: string;
  upstreamHost: string;
}

export interface VerifiedPresign {
  cleanQuery: string;
}

export function stripAmzQueryParams(pairs: [string, string][]): string {
  return pairs
    .filter(([key]) => !key.toLowerCase().startsWith("x-amz-"))
    .map(([key, value]) => `${key}=${value}`)
    .join("&");
}

export async function verifyPresignedRequest(
  input: VerifyPresignInput,
  client: ClientAuth,
): Promise<VerifiedPresign> {
  const pairs = parseRawQuery(input.rawQuery);
  const queryParam = (name: string): string | undefined => {
    const pair = pairs.find(([key]) => key.toLowerCase() === name.toLowerCase());
    return pair === undefined ? undefined : decodeURIComponent(pair[1]);
  };

  const algorithm = queryParam("X-Amz-Algorithm");
  const credential = queryParam("X-Amz-Credential");
  const amzDate = queryParam("X-Amz-Date");
  const expires = queryParam("X-Amz-Expires");
  const signedHeadersParam = queryParam("X-Amz-SignedHeaders");
  const signature = queryParam(SIGNED_QUERY_PARAM);
  if (
    algorithm === undefined ||
    credential === undefined ||
    amzDate === undefined ||
    !/^\d{8}T\d{6}Z$/.test(amzDate) ||
    expires === undefined ||
    signedHeadersParam === undefined ||
    signature === undefined ||
    !/^[0-9a-f]{64}$/i.test(signature)
  ) {
    throw new PresignError("Malformed presigned URL", "AccessDenied");
  }

  const credentialParts = credential.split("/");
  const keyId = credentialParts[0];
  const dateStamp = credentialParts[1];
  const credentialRegion = credentialParts[2];
  if (
    keyId === undefined ||
    dateStamp === undefined ||
    credentialRegion === undefined ||
    credentialParts[3] !== "s3" ||
    credentialParts[4] !== "aws4_request" ||
    dateStamp !== amzDate.slice(0, 8)
  ) {
    throw new PresignError("Malformed credential scope", "AccessDenied");
  }
  if (!timingSafeEqual(keyId, client.keyId)) {
    throw new PresignError("Unknown access key id", "InvalidAccessKeyId");
  }
  if (!/^\d+$/.test(expires) || Number(expires) > MAX_PRESIGN_EXPIRES_SECONDS) {
    throw new PresignError(`X-Amz-Expires must be <= ${MAX_PRESIGN_EXPIRES_SECONDS} seconds`, "AccessDenied");
  }

  const signedAt = Date.parse(
    `${amzDate.slice(0, 4)}-${amzDate.slice(4, 6)}-${amzDate.slice(6, 8)}T${amzDate.slice(9, 11)}:${amzDate.slice(11, 13)}:${amzDate.slice(13, 15)}Z`,
  );
  if (!Number.isFinite(signedAt) || signedAt + Number(expires) * 1000 < Date.now()) {
    throw new PresignError("Presigned URL expired", "AccessDenied", "Request has expired");
  }

  const signedHeaders = signedHeadersParam
    .split(";")
    .map((name) => name.trim().toLowerCase())
    .filter(Boolean);
  const queryPairs = pairs.filter(([key]) => key !== SIGNED_QUERY_PARAM);
  const credentialScope = `${dateStamp}/${credentialRegion}/s3/aws4_request`;
  const signingKey = await deriveSigningKey(client.secret, dateStamp, credentialRegion);
  const hostCandidates = [
    ...new Set([input.clientHost, input.upstreamHost].filter((v): v is string => v !== undefined)),
  ];
  const queryVariants: CanonicalQueryOptions[] = [
    { sort: true, reencode: true },
    { sort: true, reencode: false },
    { sort: false, reencode: true },
    { sort: false, reencode: false },
  ];
  const payloadVariants = ["UNSIGNED-PAYLOAD", EMPTY_PAYLOAD_HASH];

  let missingHeader: string | undefined;
  let standardAttempt = "";
  for (const host of hostCandidates) {
    const canonicalHeaders: [string, string][] = [];
    let missing = false;
    for (const name of signedHeaders) {
      if (name === "host") {
        canonicalHeaders.push(["host", host]);
        continue;
      }
      const value = lookupSignedHeader(input.headers, name);
      if (value === undefined) {
        missing = true;
        missingHeader = name;
        break;
      }
      canonicalHeaders.push([name, value]);
    }
    if (missing) continue;

    const headersBlock = canonicalHeaders
      .map(([name, value]) => `${name}:${value.trim().replace(/\s+/g, " ")}\n`)
      .join("");
    for (const variant of queryVariants) {
      for (const payloadHash of payloadVariants) {
        const canonicalRequest = [
          input.method,
          input.path,
          canonicalizeQuery(queryPairs, variant),
          headersBlock,
          signedHeaders.join(";"),
          payloadHash,
        ].join("\n");
        if (standardAttempt === "" && host === input.clientHost) {
          standardAttempt = canonicalRequest;
        }
        const stringToSign = [
          "AWS4-HMAC-SHA256",
          amzDate,
          credentialScope,
          await sha256Hex(canonicalRequest),
        ].join("\n");

        if (timingSafeEqual(await hmacHex(signingKey, stringToSign), signature.toLowerCase())) {
          return { cleanQuery: stripAmzQueryParams(pairs) };
        }
      }
    }
  }
  if (missingHeader !== undefined) {
    throw new PresignError(
      `Signed header missing from request: ${missingHeader}`,
      "SignatureDoesNotMatch",
      `header '${missingHeader}' is listed in signed headers, but is not present`,
    );
  }
  throw new PresignError(
    `SignatureDoesNotMatch. Check: (1) PROXY_APP_SECRET is identical to the secret used by the ` +
      `backend to sign; (2) the uploader sends exactly the signed headers (${signedHeaders.join(", ")}). ` +
      `Canonical request (standard form): ${standardAttempt.replaceAll("\n", "\\n")}`,
  );
}

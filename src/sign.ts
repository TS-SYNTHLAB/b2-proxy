import { canonicalizeQuery, parseRawQuery } from "./query.js";

const encoder = new TextEncoder();

export function toAmzDate(date: Date): string {
  return date.toISOString().replace(/[:-]|\.\d{3}/g, "");
}

function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

async function hmacSha256(key: Uint8Array<ArrayBuffer>, data: string): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(data)));
}

export const EMPTY_PAYLOAD_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

export async function sha256Hex(data: string | Uint8Array<ArrayBuffer>): Promise<string> {
  const bytes = typeof data === "string" ? encoder.encode(data) : data;
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

export async function hmacHex(key: Uint8Array<ArrayBuffer>, data: string): Promise<string> {
  return toHex(await hmacSha256(key, data));
}

export async function deriveSigningKey(
  secret: string,
  dateStamp: string,
  region: string,
): Promise<Uint8Array<ArrayBuffer>> {
  let key = encoder.encode(`AWS4${secret}`);
  for (const part of [dateStamp, region, "s3", "aws4_request"]) {
    key = await hmacSha256(key, part);
  }
  return key;
}

export interface SignInput {
  method: string;
  path: string;
  rawQuery: string;
  headers: Record<string, string>;
  payloadHash: string;
  keyId: string;
  appKey: string;
  region: string;
  amzDate: string;
}

export async function signRequest(input: SignInput): Promise<string> {
  const dateStamp = input.amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/${input.region}/s3/aws4_request`;

  const entries = Object.entries(input.headers)
    .map(([name, value]): [string, string] => [
      name.toLowerCase(),
      value.trim().replace(/\s+/g, " "),
    ])
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));

  const canonicalHeaders = entries.map(([name, value]) => `${name}:${value}\n`).join("");
  const signedHeaders = entries.map(([name]) => name).join(";");
  const canonicalQuery = canonicalizeQuery(parseRawQuery(input.rawQuery), { sort: true, reencode: true });

  const canonicalRequest = [
    input.method,
    input.path,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders,
    input.payloadHash,
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    input.amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  const key = await deriveSigningKey(input.appKey, dateStamp, input.region);
  const signature = await hmacHex(key, stringToSign);

  return `AWS4-HMAC-SHA256 Credential=${input.keyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;
}

// Verifies a presigned URL locally with standard SigV4 (the same form AWS/B2 expect).
//
// Usage:
//   node scripts/check-presign.mjs "<presigned-url>" "<secret>" [content-type] [content-length]
//
// content-length is optional: when omitted, the script discovers it by brute force (0..30 MB).
//
// Example:
//   node scripts/check-presign.mjs "https://storage.example.com/b/a.zip?X-Amz-..." "K005..." "application/zip"
import { createHash, createHmac } from "node:crypto";

const [, , urlArg, secret, contentTypeArg, contentLengthArg] = process.argv;
if (!urlArg || !secret) {
  console.error('Usage: node scripts/check-presign.mjs "<url>" "<secret>" [content-type] [content-length]');
  process.exit(1);
}

const url = new URL(urlArg);
const params = url.search.slice(1).split("&").map((pair) => {
  const index = pair.indexOf("=");
  return index === -1 ? [pair, ""] : [pair.slice(0, index), pair.slice(index + 1)];
});
const get = (name) => {
  const pair = params.find(([key]) => key === name);
  return pair === undefined ? undefined : decodeURIComponent(pair[1]);
};

const credential = get("X-Amz-Credential");
const amzDate = get("X-Amz-Date");
const signedHeadersParam = get("X-Amz-SignedHeaders");
const signature = get("X-Amz-Signature");
if (!credential || !amzDate || !signedHeadersParam || !signature) {
  console.error("URL does not look like a SigV4 presigned URL (missing X-Amz-* params)");
  process.exit(1);
}

const [keyId, dateStamp, region] = credential.split("/");
const signedHeaders = signedHeadersParam.split(";");
const method = "PUT";

const needsContentType = signedHeaders.includes("content-type");
const needsContentLength = signedHeaders.includes("content-length");
if (needsContentType && !contentTypeArg) {
  console.error('Pass the signed content-type. Ex: node scripts/check-presign.mjs "<url>" "<secret>" "application/zip"');
  process.exit(1);
}

const enc = (value) =>
  encodeURIComponent(value).replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase());

const canonicalQuery = params
  .filter(([key]) => key !== "X-Amz-Signature")
  .map(([key, value]) => [enc(decodeURIComponent(key)), enc(decodeURIComponent(value))])
  .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  .map(([key, value]) => `${key}=${value}`)
  .join("&");

const hmac = (key, data) => createHmac("sha256", key).update(data, "utf8").digest();
const signingKey = hmac(hmac(hmac(hmac("AWS4" + secret, dateStamp), region), "s3"), "aws4_request");

function signatureFor(contentLength) {
  const headerValues = {
    host: url.host,
    "content-type": contentTypeArg,
    "content-length": String(contentLength),
  };
  const canonicalHeaders = signedHeaders.map((name) => `${name}:${headerValues[name]}\n`).join("");
  const canonicalRequest = [
    method,
    url.pathname,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders.join(";"),
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    `${dateStamp}/${region}/s3/aws4_request`,
    createHash("sha256").update(canonicalRequest, "utf8").digest("hex"),
  ].join("\n");
  return createHmac("sha256", signingKey).update(stringToSign, "utf8").digest("hex");
}

console.log("keyId          :", keyId);
console.log("signedHeaders  :", signedHeaders.join(";"));
console.log("URL signature  :", signature);

if (contentLengthArg !== undefined) {
  const expected = signatureFor(Number(contentLengthArg));
  console.log("expected       :", expected);
  console.log("");
  console.log(expected === signature
    ? "MATCH — the URL is valid for this secret and these values."
    : "MISMATCH — wrong secret, or content-length/content-type differ from the signed ones, or non-standard signer.");
  process.exit(expected === signature ? 0 : 1);
}

if (!needsContentLength) {
  const expected = signatureFor(0);
  console.log("expected       :", expected);
  console.log("");
  console.log(expected === signature ? "MATCH" : "MISMATCH");
  process.exit(expected === signature ? 0 : 1);
}

console.log(`content-length not provided — discovering by brute force (content-type="${contentTypeArg}", 0..30 MB)...`);
const started = Date.now();
for (let cl = 0; cl <= 30_000_000; cl++) {
  if (cl % 5_000_000 === 0) {
    console.log(`  ...${(cl / 1_000_000).toFixed(0)} MB (${((Date.now() - started) / 1000).toFixed(0)}s)`);
  }
  if (signatureFor(cl) === signature) {
    console.log("");
    console.log(`MATCH! The backend signed content-length=${cl} (${(cl / 1024).toFixed(1)} KB), content-type="${contentTypeArg}".`);
    console.log("The uploader MUST send exactly these values as headers in the PUT request.");
    process.exit(0);
  }
}
console.log("");
console.log("NO MATCH in 0..30 MB. Likely: the secret differs from the one the backend used,");
console.log("or the backend signer is non-standard. Compare the canonical request.");

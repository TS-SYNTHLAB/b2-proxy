# b2-proxy

A transparent reverse proxy for the **Backblaze B2 S3-compatible API** that works behind
your own **custom domain** — including presigned URLs. Runs on **Node.js (Fastify)** or as
a **Cloudflare Worker** from the same core.

## Why

B2 does not support custom domains via CNAME. Pointing a domain at B2 through a naive
reverse proxy breaks AWS Signature V4, because the signature covers the `Host` header: a
URL signed for `storage.example.com` never verifies at `s3.us-east-005.backblazeb2.com`.

b2-proxy solves this by **re-signing** every request with the real B2 credentials:

- **Presigned URLs** (`?X-Amz-Signature=...`): the client signature is verified (when
  client auth is enabled), the `X-Amz-*` params are stripped, and the request is re-signed
  against the B2 host. Sub-resource params (`versionId`, `x-id`, `response-content-*`)
  are preserved.
- **Regular SDK requests** (`Authorization` header): verified against the client
  credentials (when enabled), then re-signed with the B2 credentials.

Clients point any S3 SDK at your domain and everything works — presign, PUT/GET/DELETE,
multipart, range requests — on **private** buckets, without exposing your B2 credentials.

## The flow

```mermaid
sequenceDiagram
    autonumber
    participant C as Client (S3 SDK / uploader)
    participant P as b2-proxy (your domain)
    participant B as Backblaze B2

    C->>P: Signed request or presigned URL<br/>https://storage.example.com/bucket/key
    P->>P: Verify client signature<br/>(when PROXY_APP_ID/SECRET is set)
    P->>P: Strip client X-Amz-* params/headers
    P->>P: Re-sign with real B2 credentials<br/>(real payload SHA-256)
    P->>B: Forward to s3.&lt;region&gt;.backblazeb2.com
    B-->>P: Response (status, headers, streamed body)
    P-->>C: Streamed back unchanged
```

The B2 credentials never leave the proxy. Clients only ever see your domain and — when
client auth is enabled — the `PROXY_APP_ID`/`PROXY_APP_SECRET` pair, which can be rotated
independently of the bucket key.

## Features

- Two runtimes, one core: Node.js + Fastify, or Cloudflare Workers (free custom domain + TLS)
- Optional client-facing SigV4 authentication (`PROXY_APP_ID` / `PROXY_APP_SECRET`)
- Presigned URLs generated against your domain just work (verify + re-sign)
- Real SHA-256 payload hashing on re-sign (maximum B2 compatibility for PUTs)
- Startup credential validation against `b2_authorize_account` (catches wrong region,
  master key misuse, and typos before the first request)
- Streams responses; S3-shaped XML errors; `x-b2-proxy: 1` marker header for debugging

## Project structure

```
src/
  config.ts    env parsing and validation
  query.ts     raw query-string handling (byte-preserving) and canonicalization variants
  headers.ts   header helpers
  sign.ts      AWS Signature V4 signing (Web Crypto — runs on Node and Workers)
  auth.ts      client-facing SigV4 verification (header auth and presigned URLs)
  upstream.ts  upstream URL building and forwarding
  proxy.ts     core: verify the client signature, then re-sign with B2 credentials
  validate.ts  startup credential checks against b2_authorize_account
  server.ts    Node entrypoint (Fastify)
  worker.ts    Cloudflare Workers entrypoint
scripts/
  check-presign.mjs  standalone presigned-URL verifier (no dependencies)
test-proxy.ts        test suite (runs against a local mock upstream)
```

## Configuration

| Variable           | Required | Description |
| ------------------ | -------- | ----------- |
| `UPSTREAM_URL`     | yes      | B2 S3 endpoint, e.g. `https://s3.us-west-004.backblazeb2.com` |
| `B2_KEY_ID`        | yes      | Application key ID (**not** the master key) |
| `B2_APP_KEY`       | yes      | Application key |
| `B2_REGION`        | no       | Region (derived from the B2 hostname, e.g. `s3.us-west-004...` → `us-west-004`) |
| `B2_BUCKET`        | no       | Pin a bucket; alternative to putting the bucket in the `UPSTREAM_URL` path |
| `PROXY_APP_ID`     | no       | Key ID clients use to sign (see below) |
| `PROXY_APP_SECRET` | no       | Secret clients use to sign |
| `PORT` / `HOST`    | no       | Node bind (default `3000` / `0.0.0.0`) |
| `BODY_LIMIT`       | no       | Max request body in bytes (default 512 MiB) |

Requests are forwarded path-style: `https://your-domain.com/<bucket>/<key>`. To pin a
bucket and shorten public URLs, set `B2_BUCKET=my-bucket` — the path then is just the key.

> **Important — `InvalidAccessKeyId`** comes in two flavors:
>
> - **"Malformed Access Key Id"** — malformed credential: you used the **master
>   application key** (the one on the main Buckets page — it does **not** work with the
>   S3 API), or the value has extra whitespace/newlines. Create a dedicated key at
>   **B2 Cloud Storage → Application Keys → Add a New Application Key** and use its
>   `keyID` (25 chars, starts with `005`).
> - **"The key '005...' is not valid"** — the key is well-formed, but the request hit the
>   **wrong region endpoint**. `UPSTREAM_URL` must be the endpoint of your bucket's region
>   (e.g. `https://s3.us-east-005.backblazeb2.com`).
>
> At startup, the proxy validates the credentials against `b2_authorize_account` for real:
> it warns if the key is rejected (401), and if `UPSTREAM_URL` diverges from the key's
> actual endpoint it prints the correct endpoint in the warning.

## Running on Node (Fastify)

```bash
npm install
cp .env.example .env   # fill in the credentials

npm run dev            # development (watch)
npm run build          # compiles to dist/
npm start              # production (node dist/server.js)
npm test               # test suite against a local mock upstream
```

Then point your domain (nginx/Caddy with TLS) at the proxy port.

## Running on Cloudflare Workers

```bash
npm install

wrangler secret put B2_KEY_ID
wrangler secret put B2_APP_KEY
# Optional, to require client authentication:
# wrangler secret put PROXY_APP_ID
# wrangler secret put PROXY_APP_SECRET

npm run dev:worker                 # local development
npm run deploy                     # deploy
```

Then attach the custom domain in **Workers → b2-proxy → Settings → Domains & Routes**.
For local dev, copy the secrets into a `.dev.vars` file.

> **Warning — two config files:** both `wrangler.toml` and `wrangler.jsonc` exist.
> **When both exist, Wrangler only uses `wrangler.jsonc`** — changes to `wrangler.toml`
> are ignored. Edit `wrangler.jsonc` (or delete one of them). A stale `UPSTREAM_URL` in
> the "winning" file is the classic cause of `InvalidAccessKeyId: The key ... is not valid`.

## Client authentication (optional)

By default, anyone who knows the domain can operate the bucket. To close that, set
`PROXY_APP_ID` + `PROXY_APP_SECRET`. Every request then needs a valid client signature:

- **Regular requests**: the client signs with SigV4 using those credentials, exactly like
  a normal S3 client. The proxy recomputes and compares the signature (constant-time),
  then re-signs with the real B2 credentials. The region the client signs with can be
  anything (including `auto`) — the proxy derives the key with the client's own scope.
- **Presigned URLs** generated against your domain are verified the same way (HMAC over
  the canonical request, accepting either your domain or the B2 host), then re-signed.

> Use credentials **different** from the B2 ones: clients should only ever know the proxy
> pair; the real bucket key stays on the proxy.

Example with `aws-cli` pointed at the proxy:

```bash
aws configure --profile proxy
# Access Key ID:     value of PROXY_APP_ID
# Secret Access Key: value of PROXY_APP_SECRET
# Region:            same as the bucket (e.g. us-east-005)

aws s3 cp file.zip s3://my-bucket/file.zip \
  --profile proxy \
  --endpoint-url https://storage.example.com
```

Generating a presigned URL against your domain (AWS SDK v3):

```ts
const s3 = new S3Client({
  endpoint: "https://storage.example.com",
  region: "auto",
  forcePathStyle: true,
  credentials: { accessKeyId: PROXY_APP_ID, secretAccessKey: PROXY_APP_SECRET },
});
const url = await getSignedUrl(s3, new PutObjectCommand({
  Bucket: "my-bucket",
  Key: "uploads/file.zip",
  ContentType: "application/zip",
  ContentLength: 33676,
}), { expiresIn: 120 });
```

The uploader must then send exactly the signed headers (`content-type`, `content-length`)
in the PUT.

## How requests are handled

- **Presigned** (`?X-Amz-Signature=...`): with client auth on, the signature is verified
  (multiple canonicalization variants are accepted: sorted/unsorted query, raw/re-encoded
  params, `UNSIGNED-PAYLOAD`/empty payload hash — so non-standard signers and tools that
  re-encode the URL still verify). Then `X-Amz-*` params are stripped and the request is
  re-signed with the B2 credentials.
- **Regular**: the proxy strips the client's `x-amz-*`/`authorization` and signs with the
  B2 credentials. Only controlled, stable headers are signed (`host`, `content-type`,
  `range`, `cache-control`, `expires`, `if-*`, plus the proxy-generated `x-amz-*`).
  Volatile or platform-injected headers — `user-agent`, `accept-encoding`, `cf-*`
  (Cloudflare), `x-forwarded-*` — are forwarded when useful but **never signed**, since
  they can change in transit and would break the signature.
- The B2 response (status, headers like `content-range`, streamed body) is returned to the
  client unmodified.

## Troubleshooting

**Verify a presigned URL locally** (no proxy involved — tells you whether the problem is
the backend signer or the credentials):

```bash
node scripts/check-presign.mjs "<presigned-url>" "<PROXY_APP_SECRET>" "application/zip" 33676
```

Prints `MATCH` (URL is valid for that secret) or `MISMATCH` plus the expected canonical
request to compare against the backend. Omit the content-length and the script discovers
it by brute force (0–30 MB).

**Every response** from the proxy carries `x-b2-proxy: 1`. Client-facing errors are
generic, S3-shaped XML (`AccessDenied`, `SignatureDoesNotMatch`, `InvalidAccessKeyId`,
`Request has expired`...) — they never leak internals. The detailed reasons (which check
failed, canonical request used) go to the **server logs**: the Fastify log on Node, or
`wrangler tail` on Workers. A **generic Cloudflare error page** (530, 1016, 1017...) means
the Worker never ran — the edge failed before your code.

**Error 530 / 1016 (Origin DNS error)** — check in this order:

1. `curl -I https://your-domain/anything` — if the response does NOT have `x-b2-proxy: 1`,
   the Worker is not attached to the domain. Configure it in
   **Workers → b2-proxy → Settings → Domains & Routes → Add → Custom Domain**.
2. `UPSTREAM_URL` **must not be your own domain** (loop). It must be the B2 S3 endpoint —
   the proxy detects this and returns a 502 explaining it.
3. **Partial (CNAME) zone setups** (Business/Enterprise): every hostname the Worker
   fetches must exist in the zone's Cloudflare DNS, otherwise the subrequest fails with
   530/1016.
4. Workers cannot `fetch` plain IPs — always use a hostname in `UPSTREAM_URL`.

## Notes

- Request bodies are buffered (limit `BODY_LIMIT`, default 512 MiB); responses stream.
- Browser clients need CORS configured on the B2 bucket (the proxy just forwards the
  `access-control-*` headers).
- Duplicate query params are signed per the current SigV4 spec on re-sign (all values
  signed); presigned URLs are verified, so they are not affected.

## Credits

Built with [Kimi](https://www.kimi.com/) (Moonshot AI) via [OpenCode](https://opencode.ai).

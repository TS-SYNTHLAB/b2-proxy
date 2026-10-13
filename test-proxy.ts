import http from "node:http";
import assert from "node:assert";
import aws4 from "aws4";
import { handleProxy } from "./src/proxy.js";
import { resolveConfig } from "./src/config.js";
import { endpointMismatchWarning } from "./src/validate.js";
import { deriveSigningKey, hmacHex, sha256Hex } from "./src/sign.js";
import { encodeCanonicalQuery } from "./src/query.js";

interface SeenRequest {
  method?: string;
  url?: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

const seen: SeenRequest[] = [];

const upstream = http.createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    seen.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
});

await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
const upstreamAddress = upstream.address();
if (upstreamAddress === null || typeof upstreamAddress === "string") {
  throw new Error("Failed to start upstream mock");
}
const upstreamOrigin = `http://127.0.0.1:${upstreamAddress.port}`;
const upstreamHost = new URL(upstreamOrigin).host;

const config = resolveConfig({
  UPSTREAM_URL: upstreamOrigin,
  B2_KEY_ID: "testkeyid",
  B2_APP_KEY: "testappkey",
  B2_REGION: "us-west-004",
});

const proxyHost = "files.example.com";

// 0) Config: region derivation, bucket in path, B2_BUCKET, credential trimming
{
  const fromHost = (url: string) =>
    resolveConfig({ UPSTREAM_URL: url, B2_KEY_ID: "k", B2_APP_KEY: "s" }).region;
  assert.equal(fromHost("https://s3.us-west-004.backblazeb2.com"), "us-west-004");
  assert.equal(fromHost("https://s3.eu-central-003.backblazeb2.com"), "eu-central-003");
  assert.equal(fromHost("https://mybucket.s3.us-east-005.backblazeb2.com"), "us-east-005");
  assert.equal(fromHost("https://s3.us-west-004.backblazeb2.com/mybucket"), "us-west-004");

  const withBucket = resolveConfig({
    UPSTREAM_URL: "https://s3.us-west-004.backblazeb2.com/my-bucket",
    B2_KEY_ID: "k",
    B2_APP_KEY: "s",
  });
  assert.equal(withBucket.upstream, "https://s3.us-west-004.backblazeb2.com/my-bucket");
  assert.equal(withBucket.region, "us-west-004");

  const bucketEnv = resolveConfig({
    UPSTREAM_URL: "https://s3.us-west-004.backblazeb2.com",
    B2_KEY_ID: "k",
    B2_APP_KEY: "s",
    B2_BUCKET: "other-bucket",
  });
  assert.equal(bucketEnv.upstream, "https://s3.us-west-004.backblazeb2.com/other-bucket");

  const trimmed = resolveConfig({
    UPSTREAM_URL: "https://s3.us-west-004.backblazeb2.com",
    B2_KEY_ID: "  005abc\n",
    B2_APP_KEY: "  K005secret  ",
  });
  assert.equal(trimmed.keyId, "005abc");
  assert.equal(trimmed.appKey, "K005secret");

  const regionOverride = resolveConfig({
    UPSTREAM_URL: "https://s3.us-west-004.backblazeb2.com",
    B2_KEY_ID: "k",
    B2_APP_KEY: "s",
    B2_REGION: "us-east-005",
  });
  assert.equal(regionOverride.region, "us-east-005");

  assert.throws(
    () => resolveConfig({ UPSTREAM_URL: "https://s3.us-west-004.backblazeb2.com", B2_KEY_ID: "k", B2_APP_KEY: "s", PROXY_APP_ID: "x" }),
    /must be set together/,
  );
  console.log("OK 0 - config: region, bucket in path, B2_BUCKET, credential trimming");
}

// 1) Open mode (no PROXY_APP_ID): presigned URL is cleaned and re-signed
{
  const presignedQuery =
    "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=abc%2F20240101%2Fus-west-004%2Fs3%2Faws4_request&X-Amz-Date=20240101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host&X-Amz-Signature=deadbeef&x-id=GetObject";
  const res = await handleProxy(
    {
      method: "GET",
      path: "/my-bucket/photos/cat%20(1).png",
      rawQuery: presignedQuery,
      headers: [
        ["host", proxyHost],
        ["user-agent", "test-agent"],
        ["range", "bytes=0-10"],
        ["cf-ipcountry", "BR"],
        ["x-amz-security-token", "client-token"],
      ],
      body: null,
    },
    config,
  );
  assert.equal(res.status, 200);
  await res.text();

  const req = seen.at(-1)!;
  assert.equal(req.url, "/my-bucket/photos/cat%20(1).png?x-id=GetObject", "X-Amz-* stripped from query");
  assert.match(req.headers["authorization"] as string, /Credential=testkeyid\//, "proxy re-signs with B2 credentials");
  assert.equal(req.headers["range"], "bytes=0-10");
  assert.equal(req.headers["user-agent"], "test-agent");
  assert.equal(req.headers["x-amz-security-token"], undefined);
  assert.equal(req.headers["cf-ipcountry"], undefined);
  console.log("OK 1 - open mode: presigned cleaned and re-signed");
}

// 2) Plain request: proxy re-signs server-side; signature matches aws4 reference
{
  seen.length = 0;
  const res = await handleProxy(
    {
      method: "PUT",
      path: "/my-bucket/dir/file.txt",
      rawQuery: "x-id=PutObject&acl=private&b=x",
      headers: [
        ["host", proxyHost],
        ["content-type", "text/plain"],
        ["content-length", "5"],
        ["accept", "*/*"],
        ["accept-encoding", "br, gzip"],
        ["user-agent", "test-agent"],
        ["cf-ipcountry", "BR"],
        ["cf-connecting-ip", "1.2.3.4"],
        ["cdn-loop", "cloudflare"],
        ["x-forwarded-for", "5.6.7.8"],
        ["x-custom-app", "v1"],
        ["x-amz-acl", "private"],
        ["x-amz-date", "20200101T000000Z"],
      ],
      body: new TextEncoder().encode("hello"),
    },
    config,
  );
  assert.equal(res.status, 200);
  await res.text();

  const req = seen.at(-1)!;
  assert.equal(req.url, "/my-bucket/dir/file.txt?x-id=PutObject&acl=private&b=x", "query keeps original order");
  assert.equal(req.body, "hello");
  assert.equal(req.headers["content-type"], "text/plain");
  assert.equal(req.headers["x-custom-app"], "v1", "custom headers forwarded unsigned");
  assert.equal(req.headers["x-forwarded-for"], "5.6.7.8");
  assert.equal(req.headers["x-amz-acl"], undefined, "client x-amz headers stripped");
  assert.equal(req.headers["cf-ipcountry"], undefined, "cf-* headers stripped before send");
  assert.equal(req.headers["cf-connecting-ip"], undefined);
  assert.equal(req.headers["cdn-loop"], undefined);
  assert.equal(
    req.headers["x-amz-content-sha256"],
    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
    "real payload hash (sha256 of 'hello')",
  );
  assert.match(req.headers["x-amz-date"] as string, /^\d{8}T\d{6}Z$/);

  const auth = req.headers["authorization"] as string;
  const authMatch = /^AWS4-HMAC-SHA256 Credential=testkeyid\/(\d{8})\/us-west-004\/s3\/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=([0-9a-f]{64})$/.exec(auth);
  assert.ok(authMatch, `unexpected Authorization format: ${auth}`);
  assert.equal(
    authMatch[2],
    "content-type;host;x-amz-content-sha256;x-amz-date",
    "only explicit, controlled headers are signed",
  );

  const reference = aws4.sign(
    {
      host: upstreamHost,
      path: "/my-bucket/dir/file.txt?x-id=PutObject&acl=private&b=x",
      method: "PUT",
      service: "s3",
      region: "us-west-004",
      headers: {
        "Content-Type": "text/plain",
        "X-Amz-Content-Sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        "X-Amz-Date": req.headers["x-amz-date"] as string,
      },
    },
    { accessKeyId: "testkeyid", secretAccessKey: "testappkey" },
  );
  const referenceSignature = /Signature=([0-9a-f]{64})/.exec(reference.headers!["Authorization"] as string)![1];
  assert.equal(authMatch[3], referenceSignature, "signature must match the aws4 reference");
  console.log("OK 2 - signature matches aws4 reference, volatile headers unsigned");
}

// 3) UPSTREAM_URL pointing at the proxy's own domain is rejected
{
  const loopConfig = resolveConfig({
    UPSTREAM_URL: "https://storage.example.com",
    B2_KEY_ID: "k",
    B2_APP_KEY: "s",
    B2_REGION: "us-east-005",
  });
  await assert.rejects(
    () =>
      handleProxy(
        { method: "GET", path: "/b/f.png", rawQuery: "", headers: [["host", "storage.example.com"]], body: null },
        loopConfig,
      ),
    /points to the proxy's own host/,
  );
  console.log("OK 3 - upstream loop detected and rejected");
}

// 4) Client SigV4 auth (PROXY_APP_ID + PROXY_APP_SECRET)
{
  const authConfig = resolveConfig({
    UPSTREAM_URL: upstreamOrigin,
    B2_KEY_ID: "testkeyid",
    B2_APP_KEY: "testappkey",
    B2_REGION: "us-west-004",
    PROXY_APP_ID: "clientid",
    PROXY_APP_SECRET: "clientsecret",
  });

  const proxyInput = {
    method: "PUT",
    path: "/my-bucket/new-file.txt",
    rawQuery: "x-id=PutObject",
    headers: [
      ["host", proxyHost],
      ["content-type", "text/plain"],
      ["x-amz-date", "20240101T120000Z"],
      ["x-amz-content-sha256", "UNSIGNED-PAYLOAD"],
    ] as [string, string][],
    body: new TextEncoder().encode("hello"),
  };

  {
    seen.length = 0;
    const res = await handleProxy(proxyInput, authConfig);
    const text = await res.text();
    assert.equal(res.status, 403);
    assert.match(text, /AccessDenied/);
    assert.equal(seen.length, 0, "upstream must not be called without client auth");
  }

  {
    seen.length = 0;
    const res = await handleProxy(
      { ...proxyInput, headers: [...proxyInput.headers, ["authorization", "AWS4-HMAC-SHA256 Credential=other/20240101/us-west-004/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=00"]] },
      authConfig,
    );
    assert.equal(res.status, 403);
    assert.equal(seen.length, 0);
  }

  {
    seen.length = 0;
    const clientSigned = aws4.sign(
      {
        host: proxyHost,
        path: "/my-bucket/new-file.txt?x-id=PutObject",
        method: "PUT",
        service: "s3",
        region: "us-west-004",
        headers: {
          "Content-Type": "text/plain",
          "X-Amz-Date": "20240101T120000Z",
          "X-Amz-Content-Sha256": "UNSIGNED-PAYLOAD",
        },
      },
      { accessKeyId: "clientid", secretAccessKey: "clientsecret" },
    );
    const clientAuth = clientSigned.headers!["Authorization"] as string;
    assert.match(clientAuth, /SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date/);

    const res = await handleProxy(
      { ...proxyInput, headers: [...proxyInput.headers, ["authorization", clientAuth]] },
      authConfig,
    );
    const body = await res.text();
    assert.equal(res.status, 200, `valid client should pass: ${body}`);

    const req = seen.at(-1)!;
    assert.match(req.headers["authorization"] as string, /Credential=testkeyid\//, "proxy re-signs with B2 credentials");
    assert.match(req.url!, /\/my-bucket\/new-file\.txt\?x-id=PutObject/);
  }

  {
    seen.length = 0;
    const clientSigned = aws4.sign(
      {
        host: proxyHost,
        path: "/my-bucket/new-file.txt?x-id=DeleteObject",
        method: "DELETE",
        service: "s3",
        region: "auto",
        headers: { "X-Amz-Content-Sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
      },
      { accessKeyId: "clientid", secretAccessKey: "clientsecret" },
    );
    const res = await handleProxy(
      {
        method: "DELETE",
        path: "/my-bucket/new-file.txt",
        rawQuery: "x-id=DeleteObject",
        headers: [
          ["host", proxyHost],
          ["x-amz-date", clientSigned.headers!["X-Amz-Date"] as string],
          ["x-amz-content-sha256", clientSigned.headers!["X-Amz-Content-Sha256"] as string],
          ["authorization", clientSigned.headers!["Authorization"] as string],
        ],
        body: null,
      },
      authConfig,
    );
    const body = await res.text();
    assert.equal(res.status, 200, `client with region=auto should pass: ${body}`);
    console.log("OK 4d - client with a different region than the proxy accepted");
  }
  console.log("OK 4 - client SigV4 auth (rejects missing credentials, accepts valid signature)");
}

// 5) Endpoint mismatch detection
{
  assert.equal(
    endpointMismatchWarning("https://s3.us-east-005.backblazeb2.com", "s3.us-east-005.backblazeb2.com"),
    null,
  );
  assert.equal(
    endpointMismatchWarning("https://my-bucket.s3.us-east-005.backblazeb2.com", "s3.us-east-005.backblazeb2.com"),
    null,
    "virtual-hosted style must match the endpoint",
  );
  const mismatch = endpointMismatchWarning("https://s3.us-west-004.backblazeb2.com", "s3.us-east-005.backblazeb2.com");
  assert.ok(mismatch !== null);
  assert.match(mismatch, /us-west-004/);
  assert.match(mismatch, /s3\.us-east-005\.backblazeb2\.com/);
  console.log("OK 5 - endpoint mismatch detected and explained");
}

// 6) Presigned URL with client auth: verified, cleaned, re-signed with B2 credentials
{
  const authConfig = resolveConfig({
    UPSTREAM_URL: upstreamOrigin,
    B2_KEY_ID: "testkeyid",
    B2_APP_KEY: "testappkey",
    B2_REGION: "us-west-004",
    PROXY_APP_ID: "clientid",
    PROXY_APP_SECRET: "clientsecret",
  });

  const signed = aws4.sign(
    {
      host: proxyHost,
      path: "/my-bucket/dir/file.txt?x-id=PutObject&versionId=42",
      method: "PUT",
      service: "s3",
      region: "auto",
      signQuery: true,
      headers: { "Content-Type": "text/plain" },
    },
    { accessKeyId: "clientid", secretAccessKey: "clientsecret" },
  );
  const signedPath = (signed as { path?: string }).path ?? "";
  const signedUrl = new URL(signedPath, `https://${proxyHost}`);
  const clientReqHeaders: [string, string][] = [
    ["host", proxyHost],
    ["content-type", "text/plain"],
  ];

  seen.length = 0;
  const res = await handleProxy(
    {
      method: "PUT",
      path: signedUrl.pathname,
      rawQuery: signedUrl.search.slice(1),
      headers: clientReqHeaders,
      body: new TextEncoder().encode("hello"),
    },
    authConfig,
  );
  const resBody = await res.text();
  assert.equal(res.status, 200, `valid presigned should pass: ${resBody}`);

  const req = seen.at(-1)!;
  assert.equal(req.url, "/my-bucket/dir/file.txt?x-id=PutObject&versionId=42", "X-Amz-* stripped, sub-resources kept");
  assert.match(req.headers["authorization"] as string, /Credential=testkeyid\//, "proxy re-signs with B2 credentials");
  assert.equal(req.body, "hello");
  assert.equal(req.headers["content-type"], "text/plain");

  seen.length = 0;
  const tampered = await handleProxy(
    {
      method: "PUT",
      path: signedUrl.pathname,
      rawQuery: signedUrl.search.slice(1).replace(/X-Amz-Signature=../, "X-Amz-Signature=00"),
      headers: clientReqHeaders,
      body: new TextEncoder().encode("hello"),
    },
    authConfig,
  );
  assert.equal(tampered.status, 403);
  const tamperedText = await tampered.text();
  assert.match(tamperedText, /SignatureDoesNotMatch/);
  assert.doesNotMatch(
    tamperedText,
    /Canonical request|PROXY_APP_SECRET|standard form/,
    "client-facing errors must not leak internals (details go to logs)",
  );
  assert.equal(seen.length, 0, "upstream must not be called with an invalid signature");

  seen.length = 0;
  const signedCl = aws4.sign(
    {
      host: proxyHost,
      path: "/my-bucket/upload.bin?x-id=PutObject",
      method: "PUT",
      service: "s3",
      region: "auto",
      signQuery: true,
      headers: { "Content-Type": "application/octet-stream", "Content-Length": "11" },
    },
    { accessKeyId: "clientid", secretAccessKey: "clientsecret" },
  );
  const clUrl = new URL((signedCl as { path?: string }).path ?? "", `https://${proxyHost}`);
  assert.match(clUrl.search, /X-Amz-SignedHeaders=content-length%3Bcontent-type%3Bhost/);
  const resCl = await handleProxy(
    {
      method: "PUT",
      path: clUrl.pathname,
      rawQuery: clUrl.search.slice(1),
      headers: [
        ["host", proxyHost],
        ["content-type", "application/octet-stream"],
        ["content-length", "11"],
      ],
      body: new TextEncoder().encode("hello world"),
    },
    authConfig,
  );
  const clBody = await resCl.text();
  assert.equal(resCl.status, 200, `presigned with signed content-length should pass: ${clBody}`);
  const reqCl = seen.at(-1)!;
  assert.equal(reqCl.url, "/my-bucket/upload.bin?x-id=PutObject");
  assert.equal(reqCl.body, "hello world");
  assert.equal(reqCl.headers["content-length"], "11");
  console.log("OK 6 - presigned with client auth: verified, cleaned, re-signed");
}

// 7) Expired presigned URL is rejected before reaching upstream
{
  const authConfig = resolveConfig({
    UPSTREAM_URL: upstreamOrigin,
    B2_KEY_ID: "testkeyid",
    B2_APP_KEY: "testappkey",
    B2_REGION: "us-west-004",
    PROXY_APP_ID: "clientid",
    PROXY_APP_SECRET: "clientsecret",
  });
  const amzDate = "20200101T000000Z";
  const scope = "20200101/us-west-004/s3/aws4_request";
  const pairs: [string, string][] = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Credential", encodeURIComponent(`clientid/${scope}`)],
    ["X-Amz-Date", amzDate],
    ["X-Amz-Expires", "60"],
    ["X-Amz-SignedHeaders", "host"],
  ];
  const canonicalQuery = encodeCanonicalQuery(pairs);
  const canonicalRequest = [
    "PUT",
    "/my-bucket/x.txt",
    canonicalQuery,
    `host:${proxyHost}\n`,
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(canonicalRequest)].join("\n");
  const key = await deriveSigningKey("clientsecret", "20200101", "us-west-004");
  const signature = await hmacHex(key, stringToSign);

  seen.length = 0;
  const res = await handleProxy(
    {
      method: "PUT",
      path: "/my-bucket/x.txt",
      rawQuery: `${canonicalQuery}&X-Amz-Signature=${signature}`,
      headers: [["host", proxyHost]],
      body: new TextEncoder().encode("x"),
    },
    authConfig,
  );
  assert.equal(res.status, 403);
  assert.match(await res.text(), /AccessDenied/);
  assert.equal(seen.length, 0, "expired presigned must not reach upstream");
  console.log("OK 7 - expired presigned rejected");
}

// 8) Canonicalization variants: non-sorting signer and tool-decoded URL
{
  const authConfig = resolveConfig({
    UPSTREAM_URL: upstreamOrigin,
    B2_KEY_ID: "testkeyid",
    B2_APP_KEY: "testappkey",
    B2_REGION: "us-west-004",
    PROXY_APP_ID: "clientid",
    PROXY_APP_SECRET: "clientsecret",
  });

  const amzDate = new Date().toISOString().replace(/[:-]|\.\d{3}/g, "");
  const dateStamp = amzDate.slice(0, 8);
  const scope = `${dateStamp}/auto/s3/aws4_request`;

  const signPresign = async (canonicalQuery: string) => {
    const canonicalRequest = [
      "GET",
      "/my-bucket/file.txt",
      canonicalQuery,
      `host:${proxyHost}\n`,
      "host",
      "UNSIGNED-PAYLOAD",
    ].join("\n");
    const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, await sha256Hex(canonicalRequest)].join("\n");
    const key = await deriveSigningKey("clientsecret", dateStamp, "auto");
    return hmacHex(key, stringToSign);
  };

  {
    const unordered = `X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Date=${amzDate}&X-Amz-SignedHeaders=host&X-Amz-Credential=${encodeURIComponent(`clientid/${scope}`)}&X-Amz-Expires=300`;
    const signature = await signPresign(unordered);
    seen.length = 0;
    const res = await handleProxy(
      {
        method: "GET",
        path: "/my-bucket/file.txt",
        rawQuery: `${unordered}&X-Amz-Signature=${signature}`,
        headers: [["host", proxyHost]],
        body: null,
      },
      authConfig,
    );
    assert.equal(res.status, 200, "non-sorting signer must be accepted via variants");
    await res.text();
  }

  {
    const sorted = `X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=${encodeURIComponent(`clientid/${scope}`)}&X-Amz-Date=${amzDate}&X-Amz-Expires=300&X-Amz-SignedHeaders=host`;
    const signature = await signPresign(sorted);
    const wireQuery = `${sorted}&X-Amz-Signature=${signature}`.replaceAll("%2F", "/");
    seen.length = 0;
    const res = await handleProxy(
      {
        method: "GET",
        path: "/my-bucket/file.txt",
        rawQuery: wireQuery,
        headers: [["host", proxyHost]],
        body: null,
      },
      authConfig,
    );
    assert.equal(res.status, 200, "tool-decoded URL must be accepted via re-encode");
    await res.text();
  }
  console.log("OK 8 - canonicalization variants (order and encoding)");
}

upstream.close();
console.log("\nAll tests passed.");

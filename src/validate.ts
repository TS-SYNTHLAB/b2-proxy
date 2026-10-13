import type { Config } from "./config.js";

export function warnOnSuspiciousCredentials(config: Config, warn: (message: string) => void): void {
  if (!/^005[0-9a-f]{22}$/.test(config.keyId)) {
    warn(
      `B2_KEY_ID ("${config.keyId}") does not look like a valid application key ID ` +
        `(25 chars starting with 005). The master application key does NOT work with the S3 API — ` +
        `create an application key at https://secure.backblaze.com/app_keys.htm`,
    );
  }
  if (config.appKey.length < 20) {
    warn("B2_APP_KEY looks too short to be a valid application key.");
  }
}

export function endpointMismatchWarning(upstream: string, s3endpoint: string): string | null {
  const upstreamHost = new URL(upstream).host;
  if (upstreamHost === s3endpoint || upstreamHost.endsWith(`.${s3endpoint}`)) return null;
  return (
    `UPSTREAM_URL points to "${upstreamHost}", but the application key belongs to endpoint ` +
    `"${s3endpoint}". Set UPSTREAM_URL to https://${s3endpoint} — ` +
    `the typical symptom of this mismatch is InvalidAccessKeyId ("The key ... is not valid").`
  );
}

export async function checkB2Credentials(config: Config): Promise<string[]> {
  let response: Response;
  try {
    response = await fetch("https://api.backblazeb2.com/b2api/v3/b2_authorize_account", {
      headers: { authorization: `Basic ${btoa(`${config.keyId}:${config.appKey}`)}` },
    });
  } catch {
    return ["Could not validate credentials against B2 (network unavailable)."];
  }
  if (response.status === 401) {
    return [
      "B2 rejected the credentials with 401. Check B2_KEY_ID/B2_APP_KEY — " +
        "must be a non-master application key, without extra whitespace.",
    ];
  }
  if (!response.ok) {
    return [`Credential validation against B2 returned HTTP ${response.status}.`];
  }
  const data = (await response.json()) as {
    apiInfo?: { storageApi?: { s3endpoint?: unknown } };
  };
  const s3endpoint = data.apiInfo?.storageApi?.s3endpoint;
  if (typeof s3endpoint !== "string" || s3endpoint.length === 0) return [];
  const mismatch = endpointMismatchWarning(config.upstream, s3endpoint);
  return mismatch === null ? [] : [mismatch];
}

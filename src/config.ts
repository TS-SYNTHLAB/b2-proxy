export interface ConfigEnv {
  UPSTREAM_URL?: string;
  B2_KEY_ID?: string;
  B2_APP_KEY?: string;
  B2_REGION?: string;
  B2_BUCKET?: string;
  PROXY_APP_ID?: string;
  PROXY_APP_SECRET?: string;
}

export interface Config {
  upstream: string;
  keyId: string;
  appKey: string;
  region: string;
  clientKeyId?: string;
  clientSecret?: string;
}

function clean(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed === "" ? undefined : trimmed;
}

function required(env: ConfigEnv, name: keyof ConfigEnv): string {
  const value = clean(env[name]);
  if (value === undefined) throw new Error(`Missing required env var: ${name}`);
  return value;
}

export function resolveConfig(env: ConfigEnv): Config {
  const url = new URL(required(env, "UPSTREAM_URL"));
  const host = url.host;

  const regionMatch = /(?:^|\.)s3[.-]([a-z0-9-]+)\./.exec(host);
  const region = clean(env.B2_REGION) ?? regionMatch?.[1];
  if (region === undefined) {
    throw new Error("Could not derive B2 region from UPSTREAM_URL; set B2_REGION explicitly");
  }

  const pathSegments = url.pathname.split("/").filter(Boolean);
  if (pathSegments.length > 1) {
    throw new Error("UPSTREAM_URL path may contain at most the bucket name");
  }
  const bucket = clean(env.B2_BUCKET) ?? pathSegments[0];
  const origin = `${url.protocol}//${host}`;
  const upstream = bucket !== undefined ? `${origin}/${bucket}` : origin;

  const clientKeyId = clean(env.PROXY_APP_ID);
  const clientSecret = clean(env.PROXY_APP_SECRET);
  if ((clientKeyId === undefined) !== (clientSecret === undefined)) {
    throw new Error("PROXY_APP_ID and PROXY_APP_SECRET must be set together");
  }

  return {
    upstream,
    keyId: required(env, "B2_KEY_ID"),
    appKey: required(env, "B2_APP_KEY"),
    region,
    clientKeyId,
    clientSecret,
  };
}

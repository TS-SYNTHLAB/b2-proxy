import { resolveConfig, type Config, type ConfigEnv } from "./config.js";
import { handleProxy, type ProxyInput } from "./proxy.js";
import { checkB2Credentials, warnOnSuspiciousCredentials } from "./validate.js";

type Env = ConfigEnv & {
  UPSTREAM_URL: string;
  B2_KEY_ID: string;
  B2_APP_KEY: string;
};

let cachedConfig: Config | undefined;
let credentialsChecked = false;

async function getConfig(env: Env): Promise<Config> {
  if (cachedConfig === undefined) {
    cachedConfig = resolveConfig(env);
    warnOnSuspiciousCredentials(cachedConfig, (message) => console.warn(`[b2-proxy] ${message}`));
  }
  if (!credentialsChecked) {
    credentialsChecked = true;
    for (const warning of await checkB2Credentials(cachedConfig)) {
      console.warn(`[b2-proxy] ${warning}`);
    }
  }
  return cachedConfig;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const config = await getConfig(env);

      const url = new URL(request.url);
      const hasBody = request.method !== "GET" && request.method !== "HEAD";
      const input: ProxyInput = {
        method: request.method,
        path: url.pathname,
        rawQuery: url.search.slice(1),
        headers: [...request.headers.entries()],
        body: hasBody ? new Uint8Array(await request.arrayBuffer()) : null,
      };
      return await handleProxy(input, config, (message) => console.warn(`[b2-proxy] ${message}`));
    } catch (error) {
      console.error("[b2-proxy] unhandled error:", error);
      return new Response(JSON.stringify({ error: "b2-proxy" }), {
        status: 502,
        headers: { "content-type": "application/json", "x-b2-proxy": "1" },
      });
    }
  },
};

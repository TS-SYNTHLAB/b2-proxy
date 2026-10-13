export function buildUpstreamUrl(upstream: string, path: string, rawQuery: string): string {
  const base = `${upstream}${path}`;
  return rawQuery ? `${base}?${rawQuery}` : base;
}

export function forwardToUpstream(
  url: string,
  method: string,
  headers: Record<string, string>,
  body: Uint8Array | null,
): Promise<Response> {
  return fetch(url, { method, headers, body });
}

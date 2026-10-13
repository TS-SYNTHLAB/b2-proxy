export function parseRawQuery(rawQuery: string): [string, string][] {
  if (!rawQuery) return [];
  return rawQuery.split("&").map((pair) => {
    const index = pair.indexOf("=");
    if (index === -1) return [pair, ""];
    return [pair.slice(0, index), pair.slice(index + 1)];
  });
}

export function isPresigned(pairs: [string, string][]): boolean {
  return pairs.some(([key]) => key === "X-Amz-Signature");
}

export function encodeCanonicalQuery(pairs: [string, string][]): string {
  return canonicalizeQuery(pairs, { sort: true, reencode: false });
}

export interface CanonicalQueryOptions {
  sort: boolean;
  reencode: boolean;
}

function decodeSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function encodeRFC3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (char) => "%" + char.charCodeAt(0).toString(16).toUpperCase(),
  );
}

export function canonicalizeQuery(pairs: [string, string][], options: CanonicalQueryOptions): string {
  let normalized = pairs;
  if (options.reencode) {
    normalized = pairs.map(
      ([key, value]) =>
        [encodeRFC3986(decodeSafe(key)), encodeRFC3986(decodeSafe(value))] as [string, string],
    );
  }
  if (options.sort) {
    normalized = [...normalized].sort(([keyA, valueA], [keyB, valueB]) =>
      keyA === keyB ? (valueA < valueB ? -1 : valueA > valueB ? 1 : 0) : keyA < keyB ? -1 : 1,
    );
  }
  return normalized.map(([key, value]) => `${key}=${value}`).join("&");
}

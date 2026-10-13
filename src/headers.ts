export const UNSIGNED_PAYLOAD = "UNSIGNED-PAYLOAD";

export function findHeader(entries: Iterable<[string, string]>, name: string): string | undefined {
  for (const [rawName, value] of entries) {
    if (rawName.toLowerCase() === name) return value;
  }
  return undefined;
}

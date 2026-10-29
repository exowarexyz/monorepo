export function formatBytesValue(value: Uint8Array): string {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(value);
  if (Array.from(text).every((char) => char.charCodeAt(0) <= 0x7f)) {
    return text;
  }
  return `[${Array.from(value).join(', ')}]`;
}

export function formatKeyPreview(key: Uint8Array): string {
  return new TextDecoder('utf-8', { fatal: false }).decode(key);
}

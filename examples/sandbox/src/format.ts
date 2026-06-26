export function formatBytesValue(value: Uint8Array): string {
  try {
    const text = new TextDecoder('utf-8', { fatal: false }).decode(value);
    if (Array.from(text).every((char) => char.charCodeAt(0) <= 0x7f)) {
      return text;
    }
  } catch {
    // Fall through to byte display
  }
  return `[${Array.from(value).join(', ')}]`;
}

export function formatKeyPreview(key: Uint8Array): string {
  try {
    return new TextDecoder('utf-8', { fatal: false }).decode(key);
  } catch {
    return `[${key.byteLength} bytes]`;
  }
}

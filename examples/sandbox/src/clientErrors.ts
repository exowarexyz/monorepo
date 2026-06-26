export function isNetworkError(error: unknown): boolean {
  return error instanceof Error && (error.message.includes('fetch') || error.message.includes('network'));
}

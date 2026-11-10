export type HeadersCheckErrorCode =
  | "too_many_headers"
  | "header_too_large"
  | "invalid_url"
  | "fetch_failed";

export class HeadersCheckError extends Error {
  readonly code: HeadersCheckErrorCode;

  constructor(code: HeadersCheckErrorCode, message: string) {
    super(message);
    this.name = "HeadersCheckError";
    this.code = code;
  }
}

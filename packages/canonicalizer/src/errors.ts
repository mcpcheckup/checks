export type CanonicalizationErrorCode =
  | 'NON_FINITE_NUMBER'
  | 'UNSUPPORTED_TYPE'
  | 'DUPLICATE_KEY_AFTER_NFC'
  | 'LONE_SURROGATE'
  | 'CIRCULAR_REFERENCE'

export class CanonicalizationError extends Error {
  code: CanonicalizationErrorCode

  constructor(code: CanonicalizationErrorCode, message: string) {
    super(message)
    this.name = 'CanonicalizationError'
    this.code = code
  }
}

export class ProtocolError extends Error {
  constructor(
    public readonly code: string,
    public readonly status = 400,
  ) {
    super(code);
  }
}
export const fail = (code: string, status = 400): never => {
  throw new ProtocolError(code, status);
};

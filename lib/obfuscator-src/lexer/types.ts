export interface Position {
  line: number;
  column: number;
  offset: number;
}

export interface LexError {
  message: string;
  loc: { start: Position; end: Position };
  code?: string;
}

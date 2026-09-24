import type { Token, SourceLocation } from "../tokens.js";
import type {
  Type,
  NilType,
  SingletonType,
  IdentifierType,
  TypeofType,
  TableType,
  TablePropType,
  TableIndexerType,
  FunctionType,
  ParenType,
  UnionType,
  IntersectionType,
  TypePack,
  VariadicTypePack,
  GenericTypePack,
  Expression,
  BoundType,
  ReturnType,
  GenericTypeListWithDefaults,
} from "../ast/types.js";

export interface TypeParserContext {
  tokens: Token[];
  pos: number;
  parseExpression: () => Expression | null;
  loc: () => SourceLocation;
  mergeLoc: (loc: SourceLocation) => SourceLocation;
}

export function parseType(ctx: TypeParserContext): Type | null {
  return parseUnion(ctx);
}

function parseUnion(ctx: TypeParserContext): Type | null {
  const types: { type: Type; optional?: boolean }[] = [];
  let first = parseSimpleTypeWithOptional(ctx);
  if (!first) return null;
  types.push(first);

  while (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "|") {
    ctx.pos++;
    const next = parseSimpleTypeWithOptional(ctx);
    if (!next) return null;
    types.push(next);
  }

  if (types.length === 1 && !types[0]!.optional) return types[0]!.type;
  const start = types[0]!.type.loc.start;
  const end = types[types.length - 1]!.type.loc.end;
  return {
    type: "UnionType",
    types,
    loc: { start, end },
  } as UnionType;
}

function parseSimpleTypeWithOptional(ctx: TypeParserContext): { type: Type; optional?: boolean } | null {
  const t = parseIntersection(ctx);
  if (!t) return null;
  let optional = false;
  if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "?") {
    ctx.pos++;
    optional = true;
  }
  return { type: t, optional };
}

function parseIntersection(ctx: TypeParserContext): Type | null {
  const types: Type[] = [];
  let first = parseSimpleType(ctx);
  if (!first) return null;
  types.push(first);

  while (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "&") {
    ctx.pos++;
    const next = parseSimpleType(ctx);
    if (!next) return null;
    types.push(next);
  }

  if (types.length === 1) return types[0]!;
  const start = types[0]!.loc.start;
  const end = types[types.length - 1]!.loc.end;
  return {
    type: "IntersectionType",
    types,
    loc: { start, end },
  } as IntersectionType;
}

function isFunctionTypeLookahead(ctx: TypeParserContext): boolean {
  let depth = 0;
  let i = ctx.pos;
  const t = ctx.tokens[i];
  if (!t || t.type !== "Punctuator" || (t as any).value !== "(") return false;

  while (i < ctx.tokens.length) {
    const tok = ctx.tokens[i];
    if (tok.type === "Punctuator") {
      const val = (tok as any).value;
      if (val === "(" || val === "{" || val === "<") {
        depth++;
      } else if (val === ")" || val === "}" || val === ">") {
        depth--;
        if (depth === 0) {
          const next = ctx.tokens[i + 1];
          if (next && next.type === "Punctuator" && (next as any).value === "->") {
            return true;
          }
          return false;
        }
      }
    }
    i++;
  }
  return false;
}

function parseSimpleType(ctx: TypeParserContext): Type | null {
  const tok = ctx.tokens[ctx.pos];
  if (!tok) return null;

  if (tok.type === "Punctuator" && (tok as any).value === "...") {
    ctx.pos++;
    const inner = parseType(ctx);
    if (!inner) return null;
    return { type: "VariadicTypePack", inner, loc: tok.loc } as any;
  }

  if (tok.type === "Keyword" && (tok as any).value === "nil") {
    ctx.pos++;
    return { type: "NilType", loc: tok.loc } as NilType;
  }
  if (tok.type === "Keyword" && ((tok as any).value === "true" || (tok as any).value === "false")) {
    ctx.pos++;
    return {
      type: "SingletonType",
      value: (tok as any).value === "true",
      loc: tok.loc,
    } as SingletonType;
  }
  if (tok.type === "String") {
    ctx.pos++;
    return {
      type: "SingletonType",
      value: (tok as any).value,
      loc: tok.loc,
    } as SingletonType;
  }
  if ((tok.type === "Keyword" || tok.type === "Identifier") && (tok as any).value === "typeof") {
    ctx.pos++;
    const lp = ctx.tokens[ctx.pos];
    if (lp?.type !== "Punctuator" || (lp as any).value !== "(") return null;
    ctx.pos++;
    const exp = ctx.parseExpression();
    if (!exp) return null;
    const rp = ctx.tokens[ctx.pos];
    if (rp?.type !== "Punctuator" || (rp as any).value !== ")") return null;
    ctx.pos++;
    return {
      type: "TypeofType",
      expression: exp,
      loc: ctx.mergeLoc(exp.loc),
    } as TypeofType;
  }
  if (tok.type === "Punctuator" && (tok as any).value === "(") {
    if (isFunctionTypeLookahead(ctx)) {
      return parseFunctionType(ctx);
    }
    ctx.pos++;
    const first = parseType(ctx);
    if (!first) return null;
    if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === ",") {

      ctx.pos++;
      const types = [first];
      while (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ")") {
        if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "...") {
          ctx.pos++;
          const inner = parseType(ctx);
          if (!inner) return null;
          types.push({ type: "VariadicTypePack", inner, loc: inner.loc } as any);
        } else {
          const ty = parseType(ctx);
          if (!ty) break;
          types.push(ty);
        }
        if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ",") break;
        ctx.pos++;
      }
      if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ")") return null;
      ctx.pos++;
      return { type: "TypePack", types, loc: tok.loc } as any;
    } else {
      const rp = ctx.tokens[ctx.pos];
      if (rp?.type !== "Punctuator" || (rp as any).value !== ")") return null;
      ctx.pos++;
      return {
        type: "ParenType",
        inner: first,
        loc: ctx.mergeLoc(first.loc),
      } as ParenType;
    }
  }
  if (tok.type === "Punctuator" && (tok as any).value === "{") {
    return parseTableType(ctx);
  }
  if (tok.type === "Keyword" && (tok as any).value === "(") {
    return null;
  }
  const ft = parseFunctionType(ctx);
  if (ft) return ft;

  if (tok.type === "Identifier" || (tok.type === "Keyword" && ["any", "nil", "boolean", "number", "string", "thread", "read", "write"].includes((tok as any).value))) {
    return parseIdentifierType(ctx);
  }

  return null;
}

function parseIdentifierType(ctx: TypeParserContext): IdentifierType | null {
  const tok = ctx.tokens[ctx.pos];
  if (!tok || (tok.type !== "Identifier" && tok.type !== "Keyword")) return null;
  const start = tok.loc.start;
  let name = (tok as any).value;
  ctx.pos++;

  let module: string | undefined;
  while (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === ".") {
    ctx.pos++;
    const next = ctx.tokens[ctx.pos];
    if (next?.type !== "Identifier" && next?.type !== "Keyword") return null;
    module = name;
    name = (next as any).value;
    ctx.pos++;
  }

  let typeParams: (Type | TypePack | VariadicTypePack | GenericTypePack)[] | undefined;
  if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "<") {
    ctx.pos++;
    typeParams = parseTypeParams(ctx);
    if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ">") return null;
    ctx.pos++;
  }

  const end = ctx.tokens[ctx.pos - 1]?.loc?.end ?? start;
  return {
    type: "IdentifierType",
    name,
    module,
    typeParams,
    loc: { start, end },
  } as IdentifierType;
}

function parseTypeParams(ctx: TypeParserContext): (Type | TypePack | VariadicTypePack | GenericTypePack)[] {
  const params: (Type | TypePack | VariadicTypePack | GenericTypePack)[] = [];
  while (true) {
    const t = ctx.tokens[ctx.pos];
    if (!t || (t.type === "Punctuator" && (t as any).value === ">")) break;
    if (t.type === "Identifier" && ctx.tokens[ctx.pos + 1]?.type === "Punctuator" && (ctx.tokens[ctx.pos + 1] as any).value === "...") {
      ctx.pos += 2;
      params.push({ type: "GenericTypePack", name: (t as any).value, loc: t.loc } as GenericTypePack);
    } else if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "...") {
      ctx.pos++;
      const inner = parseType(ctx);
      if (!inner) break;
      params.push({ type: "VariadicTypePack", inner, loc: inner.loc } as VariadicTypePack);
    } else if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "(") {
      const pack = parseTypePack(ctx);
      if (pack) params.push(pack);
    } else {
      const ty = parseType(ctx);
      if (ty) params.push(ty);
      else break;
    }
    if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ",") break;
    ctx.pos++;
  }
  return params;
}

function parseTypePack(ctx: TypeParserContext): TypePack | null {
  const tok = ctx.tokens[ctx.pos];
  if (tok?.type !== "Punctuator" || (tok as any).value !== "(") return null;
  ctx.pos++;
  const types: Type[] = [];
  while (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ")") {
    if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "...") {
      ctx.pos++;
      const inner = parseType(ctx);
      if (!inner) return null;
      types.push({ type: "VariadicTypePack", inner, loc: inner.loc } as any);
    } else {
      const ty = parseType(ctx);
      if (!ty) break;
      types.push(ty);
    }
    if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ",") break;
    ctx.pos++;
  }
  if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ")") return null;
  ctx.pos++;
  return { type: "TypePack", types, loc: tok.loc } as TypePack;
}

function parseTableType(ctx: TypeParserContext): TableType | null {
  const tok = ctx.tokens[ctx.pos];
  if (tok?.type !== "Punctuator" || (tok as any).value !== "{") return null;
  const start = tok.loc.start;
  ctx.pos++;

  const next = ctx.tokens[ctx.pos];
  if (next) {
    const savedPos = ctx.pos;
    const single = parseType(ctx);
    if (single && ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "}") {
      ctx.pos++;
      return { type: "TableType", arrayType: single, loc: { start, end: ctx.tokens[ctx.pos - 1]!.loc.end } } as TableType;
    }
    ctx.pos = savedPos;
  }

  const props: (TablePropType | TableIndexerType)[] = [];
  const fieldsep = [",", ";"];

  while (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== "}") {
    const t = ctx.tokens[ctx.pos];
    if (!t) break;

    if ((t.type === "Keyword" || t.type === "Identifier") && ((t as any).value === "read" || (t as any).value === "write")) {
      const savedPos = ctx.pos;
      const ro = (t as any).value === "read";
      ctx.pos++;
      const next2 = ctx.tokens[ctx.pos];
      let processed = false;
      if (next2?.type === "Punctuator" && (next2 as any).value === "[") {
        ctx.pos++;
        const indexType = parseType(ctx);
        if (indexType && ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "]") {
          ctx.pos++;
          if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === ":") {
            ctx.pos++;
            const valueType = parseType(ctx);
            if (valueType) {
              props.push({
                type: "TableIndexerType",
                indexType,
                valueType,
                readOnly: ro,
                writeOnly: !ro,
                loc: t.loc,
              } as TableIndexerType);
              processed = true;
            }
          }
        }
      } else if (next2?.type === "Identifier" || next2?.type === "Keyword") {
        const name = (next2 as any).value;
        ctx.pos++;
        if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === ":") {
          ctx.pos++;
          const propType = parseType(ctx);
          if (propType) {
            props.push({
              type: "TablePropType",
              name,
              propType,
              readOnly: ro,
              writeOnly: !ro,
              loc: t.loc,
            } as TablePropType);
            processed = true;
          }
        }
      }

      if (!processed) {

        ctx.pos = savedPos;
        const name = (t as any).value;
        ctx.pos++;
        if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ":") break;
        ctx.pos++;
        const propType = parseType(ctx);
        if (!propType) break;
        props.push({ type: "TablePropType", name, propType, loc: t.loc } as TablePropType);
      }
    } else if (t.type === "Punctuator" && (t as any).value === "[") {
      ctx.pos++;
      const indexType = parseType(ctx);
      if (!indexType) break;
      if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== "]") break;
      ctx.pos++;
      if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ":") break;
      ctx.pos++;
      const valueType = parseType(ctx);
      if (!valueType) break;
      props.push({ type: "TableIndexerType", indexType, valueType, loc: t.loc } as TableIndexerType);
    } else if (t.type === "Identifier" || t.type === "Keyword") {
      const name = (t as any).value;
      ctx.pos++;
      if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ":") break;
      ctx.pos++;
      const propType = parseType(ctx);
      if (!propType) break;
      props.push({ type: "TablePropType", name, propType, loc: t.loc } as TablePropType);
    } else {
      break;
    }
    const sep = ctx.tokens[ctx.pos];
    if (sep?.type === "Punctuator" && fieldsep.includes((sep as any).value)) ctx.pos++;
  }

  if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== "}") return null;
  ctx.pos++;
  return { type: "TableType", props, loc: { start, end: ctx.tokens[ctx.pos - 1]!.loc.end } } as TableType;
}

function parseFunctionType(ctx: TypeParserContext): FunctionType | null {
  const tok = ctx.tokens[ctx.pos];
  if (!tok) return null;

  let generics: string[] | undefined;
  if (tok.type === "Punctuator" && (tok as any).value === "<") {
    ctx.pos++;
    generics = [];
    while (true) {
      const t = ctx.tokens[ctx.pos];
      if (!t) break;
      if (t.type === "Identifier") {
        let name = (t as any).value;
        ctx.pos++;
        if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "...") {
          ctx.pos++;
          name += "...";
        }
        generics.push(name);
      } else if (t.type === "Punctuator" && (t as any).value === ">") {
        break;
      } else {
        break;
      }
      if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ",") break;
      ctx.pos++;
    }
    if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ">") return null;
    ctx.pos++;
  }

  const lp = ctx.tokens[ctx.pos];
  if (lp?.type !== "Punctuator" || (lp as any).value !== "(") return generics ? null : null;
  ctx.pos++;

  const params: BoundType[] = [];
  while (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ")") {
    const t = ctx.tokens[ctx.pos];
    if (t?.type === "Identifier" && ctx.tokens[ctx.pos + 1]?.type === "Punctuator" && (ctx.tokens[ctx.pos + 1] as any).value === "...") {
      ctx.pos += 2;
      params.push({ type: "GenericTypePack", name: (t as any).value, loc: t.loc } as GenericTypePack);
    } else if (t?.type === "Punctuator" && (t as any).value === "...") {
      ctx.pos++;
      const inner = parseType(ctx);
      if (!inner) return null;
      params.push({ type: "VariadicTypePack", inner, loc: inner.loc } as VariadicTypePack);
    } else if (t?.type === "Identifier" || t?.type === "Keyword") {
      const name = (t as any).value;
      ctx.pos++;
      if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === ":") {
        ctx.pos++;
        const paramType = parseType(ctx);
        if (!paramType) return null;
        params.push({ name, type: paramType });
      } else {
        params.push({ type: { type: "IdentifierType", name, loc: t.loc } as IdentifierType });
      }
    } else {
      const paramType = parseType(ctx);
      if (!paramType) break;
      params.push({ type: paramType });
    }
    if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ",") break;
    ctx.pos++;
  }

  if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ")") return null;
  ctx.pos++;

  if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== "->") return null;
  ctx.pos++;

  const returnType = parseReturnType(ctx);
  if (!returnType) return null;

  return {
    type: "FunctionType",
    generics,
    params,
    returnType,
    loc: tok.loc,
  } as FunctionType;
}

export function parseReturnType(ctx: TypeParserContext): ReturnType | null {
  const t = ctx.tokens[ctx.pos];
  if (!t) return null;
  if (t.type === "Identifier" && ctx.tokens[ctx.pos + 1]?.type === "Punctuator" && (ctx.tokens[ctx.pos + 1] as any).value === "...") {
    ctx.pos += 2;
    return { type: "GenericTypePack", name: (t as any).value, loc: t.loc } as GenericTypePack;
  }
  if (t.type === "Punctuator" && (t as any).value === "...") {
    ctx.pos++;
    const inner = parseType(ctx);
    if (!inner) return null;
    return { type: "VariadicTypePack", inner, loc: t.loc } as VariadicTypePack;
  }
  if (t.type === "Punctuator" && (t as any).value === "(") {
    const pack = parseTypePack(ctx);
    return pack;
  }
  return parseType(ctx);
}

function parseTypePackOrPackDefault(ctx: TypeParserContext): any {
  const t = ctx.tokens[ctx.pos];
  if (!t) return null;
  if (t.type === "Identifier" && ctx.tokens[ctx.pos + 1]?.type === "Punctuator" && (ctx.tokens[ctx.pos + 1] as any).value === "...") {
    ctx.pos += 2;
    return { type: "GenericTypePack", name: (t as any).value, loc: t.loc } as GenericTypePack;
  }
  if (t.type === "Punctuator" && (t as any).value === "...") {
    ctx.pos++;
    const inner = parseType(ctx);
    if (!inner) return null;
    return { type: "VariadicTypePack", inner, loc: inner.loc } as VariadicTypePack;
  }
  if (t.type === "Punctuator" && (t as any).value === "(") {
    return parseTypePack(ctx);
  }
  return null;
}

export function parseGenericTypeListWithDefaults(ctx: TypeParserContext): GenericTypeListWithDefaults | null {
  const tok = ctx.tokens[ctx.pos];
  if (tok?.type !== "Punctuator" || (tok as any).value !== "<") return null;
  const start = tok.loc.start;
  ctx.pos++;

  const params: GenericTypeListWithDefaults["params"] = [];
  while (true) {
    const t = ctx.tokens[ctx.pos];
    if (!t || (t.type === "Punctuator" && (t as any).value === ">")) break;
    if (t.type === "Identifier" && (ctx.tokens[ctx.pos + 1] as any)?.value === "...") {
      const name = (t as any).value + "...";
      ctx.pos += 2;
      if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== "=") {
        params.push({ name });
      } else {
        ctx.pos++;
        const def = parseTypePackOrPackDefault(ctx);
        if (!def) break;
        params.push({ name, default: def as any });
      }
    } else if (t.type === "Identifier" || t.type === "Keyword") {
      const name = (t as any).value;
      ctx.pos++;
      let defaultType: Type | undefined;
      if (ctx.tokens[ctx.pos]?.type === "Punctuator" && (ctx.tokens[ctx.pos] as any).value === "=") {
        ctx.pos++;
        defaultType = parseType(ctx) ?? undefined;
      }
      params.push(defaultType ? { name, default: defaultType } : { name });
    } else {
      break;
    }
    if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ",") break;
    ctx.pos++;
  }

  if (ctx.tokens[ctx.pos]?.type !== "Punctuator" || (ctx.tokens[ctx.pos] as any).value !== ">") return null;
  ctx.pos++;
  return { type: "GenericTypeListWithDefaults", params, loc: { start, end: ctx.tokens[ctx.pos - 1]!.loc.end } } as GenericTypeListWithDefaults;
}

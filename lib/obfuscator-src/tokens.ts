export type SourceLocation = any
export type Token = any
export type KeywordToken = any
export type IdentifierToken = any
export type NumberToken = any
export type StringToken = any
export type InterpPartToken = any
export type PunctuatorToken = any
export type EOFToken = any
export const KEYWORDS = new Set(['and','break','continue','do','else','elseif','end','false','for','function','if','in','local','nil','not','or','repeat','return','then','true','until','while','type','export'])
export const MULTI_CHAR_OPERATORS = ['...','==','~=','<=','>=','::','->','+=','-=','*=','/=','%=','..','//','<<','>>','&=','|=','^=']
export const SINGLE_CHAR_OPERATORS = new Set(['+','-','*','/','%','^','#','&','~','|','<','>','=','(',')','{','}','[',']',';',':',',','.'])

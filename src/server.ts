#!/usr/bin/env node
/**
 * password MCP server. Two tools: `generate` and `strength`.
 *
 * `generate` produces a cryptographically random password with the
 * requested mix of character classes. `strength` runs zxcvbn against an
 * input and returns the 0-4 score plus crack-time estimates and feedback.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { randomBytes } from 'node:crypto';
import zxcvbn from 'zxcvbn';

const VERSION = '0.1.0';

const LOWER = 'abcdefghijklmnopqrstuvwxyz';
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const DIGIT = '0123456789';
const SYMBOL = '!@#$%^&*()-_=+[]{};:,.<>/?';

export interface GenerateOpts {
  length?: number;
  lowercase?: boolean;
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  exclude_ambiguous?: boolean;
}

/** Pick uniformly from `pool` using rejection sampling on 8-bit random bytes. */
function pick(pool: string, n: number): string {
  if (pool.length === 0) throw new Error('empty pool');
  const max = 256 - (256 % pool.length);
  const out: string[] = [];
  let buf = randomBytes(Math.max(n * 2, 16));
  let idx = 0;
  while (out.length < n) {
    if (idx >= buf.length) {
      buf = randomBytes(Math.max(n * 2, 16));
      idx = 0;
    }
    const b = buf[idx++];
    if (b >= max) continue;
    out.push(pool[b % pool.length]);
  }
  return out.join('');
}

export function generate(opts: GenerateOpts = {}): string {
  const length = opts.length ?? 20;
  if (length < 4 || length > 256) throw new Error('length must be in [4, 256]');
  const lower = opts.lowercase ?? true;
  const upper = opts.uppercase ?? true;
  const dig = opts.digits ?? true;
  const sym = opts.symbols ?? true;
  if (!lower && !upper && !dig && !sym) {
    throw new Error('must enable at least one character class');
  }
  // Build per-class pools, optionally filtering ambiguous characters before
  // picking — required picks must respect exclude_ambiguous too.
  const stripAmbig = (s: string) => (opts.exclude_ambiguous ? s.replace(/[0O1lI|`'"]/g, '') : s);
  const lowerP = stripAmbig(LOWER);
  const upperP = stripAmbig(UPPER);
  const digitP = stripAmbig(DIGIT);
  const symP = stripAmbig(SYMBOL);

  let pool = '';
  if (lower) pool += lowerP;
  if (upper) pool += upperP;
  if (dig) pool += digitP;
  if (sym) pool += symP;

  // Guarantee at least one char from each enabled class (post-filter).
  const required: string[] = [];
  if (lower) required.push(pick(lowerP, 1));
  if (upper) required.push(pick(upperP, 1));
  if (dig) required.push(pick(digitP, 1));
  if (sym) required.push(pick(symP, 1));

  const rest = pick(pool, length - required.length);
  const merged = (required.join('') + rest).split('');
  // Fisher-Yates with cryptographic randomness.
  const buf = randomBytes(merged.length * 4);
  for (let i = merged.length - 1; i > 0; i--) {
    const r = buf.readUInt32BE(i * 4 - 4);
    const j = r % (i + 1);
    [merged[i], merged[j]] = [merged[j], merged[i]];
  }
  return merged.join('');
}

export interface StrengthResult {
  score: 0 | 1 | 2 | 3 | 4;
  guesses_log10: number;
  crack_time_display: string;
  warning: string;
  suggestions: string[];
}

export function strength(password: string): StrengthResult {
  const r = zxcvbn(password);
  return {
    score: r.score as 0 | 1 | 2 | 3 | 4,
    guesses_log10: Math.round(r.guesses_log10 * 100) / 100,
    crack_time_display: String(r.crack_times_display.offline_slow_hashing_1e4_per_second),
    warning: r.feedback.warning ?? '',
    suggestions: r.feedback.suggestions ?? [],
  };
}

const server = new Server({ name: 'password', version: VERSION }, { capabilities: { tools: {} } });

const TOOLS = [
  {
    name: 'generate',
    description:
      'Generate a cryptographically random password. Enable lowercase/uppercase/digits/symbols (defaults: all on). Length 4-256.',
    inputSchema: {
      type: 'object',
      properties: {
        length: { type: 'integer', default: 20, minimum: 4, maximum: 256 },
        lowercase: { type: 'boolean', default: true },
        uppercase: { type: 'boolean', default: true },
        digits: { type: 'boolean', default: true },
        symbols: { type: 'boolean', default: true },
        exclude_ambiguous: { type: 'boolean', default: false, description: 'Drop 0/O/1/l/I/| etc.' },
      },
    },
  },
  {
    name: 'strength',
    description:
      'Score a password with zxcvbn. Returns score 0-4, guesses_log10, human crack-time, and feedback.',
    inputSchema: {
      type: 'object',
      properties: { password: { type: 'string' } },
      required: ['password'],
    },
  },
] as const;

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args } = req.params;
  try {
    if (name === 'generate') {
      const a = args as unknown as GenerateOpts;
      return jsonResult({ password: generate(a) });
    }
    if (name === 'strength') {
      const a = args as unknown as { password: string };
      return jsonResult(strength(a.password));
    }
    return errorResult('unknown tool: ' + name);
  } catch (err) {
    return errorResult('password tool failed: ' + (err as Error).message);
  }
});

function jsonResult(value: unknown) {
  return { content: [{ type: 'text', text: JSON.stringify(value, null, 2) }] };
}
function errorResult(message: string) {
  return { isError: true, content: [{ type: 'text', text: message }] };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write(`password MCP server v${VERSION} ready on stdio\n`);
}

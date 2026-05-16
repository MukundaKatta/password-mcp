# password-mcp

[![npm](https://img.shields.io/npm/v/@mukundakatta/password-mcp.svg)](https://www.npmjs.com/package/@mukundakatta/password-mcp)
[![mcp](https://img.shields.io/badge/protocol-MCP-blue.svg)](https://modelcontextprotocol.io)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

MCP server: generate strong passwords and score password strength with
zxcvbn. Randomness comes from Node's `crypto.randomBytes` with rejection
sampling so the distribution is uniform across the chosen alphabet.

## Tools

### `generate`

```json
{ "length": 20, "exclude_ambiguous": true }
```

→ `{ "password": "aB3xK7nQ2wP9vR4zM8tL" }`

| Field               | Default | Notes                                                              |
|---------------------|---------|--------------------------------------------------------------------|
| `length`            | 20      | 4-256                                                              |
| `lowercase`         | true    |                                                                    |
| `uppercase`         | true    |                                                                    |
| `digits`            | true    |                                                                    |
| `symbols`           | true    |                                                                    |
| `exclude_ambiguous` | false   | Drops `0 O 1 l I \|` etc.                                          |

At least one character from each enabled class is guaranteed.

### `strength`

```json
{ "password": "correct horse battery staple" }
```

→

```json
{
  "score": 4,
  "guesses_log10": 17.34,
  "crack_time_display": "centuries",
  "warning": "",
  "suggestions": []
}
```

`score` is the zxcvbn 0-4 strength rating. `guesses_log10` is the base-10 log
of the estimated guesses needed.

## Configure

```json
{ "mcpServers": { "password": { "command": "npx", "args": ["-y", "@mukundakatta/password-mcp"] } } }
```

## License

MIT.

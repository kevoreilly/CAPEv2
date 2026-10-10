# CAPE Sandbox MCP Server

Standalone Model Context Protocol (MCP) server for CAPE Sandbox.

Connect your favorite LLM client (like Claude Desktop) to a CAPE Sandbox instance seamlessly.

## Quick Start (Standalone / No Cloning Required)

If you have `uv` installed, you can run the server directly without cloning the repository:

```bash
uvx --from cape-mcp cape-mcp --url "https://cape.yourcompany.com/apiv2" --token "YOUR_API_TOKEN"
```

## Configuration for Claude Desktop

Add this to your Claude Desktop configuration file (e.g., `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS or `%APPDATA%\Claude\claude_desktop_config.json` on Windows):

```json
{
  "mcpServers": {
    "cape-sandbox": {
      "command": "uvx",
      "args": [
        "--from", "cape-mcp",
        "cape-mcp",
        "--url", "https://cape.yourcompany.com/apiv2",
        "--token", "YOUR_API_TOKEN"
      ]
    }
  }
}
```

## Environment Variables

The server can also be configured using environment variables:

- `CAPE_API_URL`: URL to your CAPE instance APIdoc (e.g., `http://localhost:8000/apiv2`).
- `CAPE_API_TOKEN`: CAPE API Authorization Token.
- `CAPE_ENABLED_MCP_TOOLS`: A comma-separated list of enabled tool names (e.g. `filecreate,tasklist`), or `*` to enable all (default in standalone mode).
- `CAPE_AUTH_REQUIRED`: Set to `true` to require token authentication for all requests.

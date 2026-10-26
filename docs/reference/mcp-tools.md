# MCP tools

**Spec ID:** CL4b / Wave 2

Thin catalog, stdio, Content-Length JSON-RPC:

`doctor` `identify` `inventory` `slice` `session_show` `evidence_get` `clone_website` `ghidra` `app_re`

Start: `reveng-debug mcp`. This is not REA’s 207-tool catalog.

Live website capture is **not** implemented inside this process. Agents use the
gotcontext-chrome MCP (`tabs_context_mcp`, `navigate`, `extract_design_tokens`,
`tab_page_assets`, `decompose_dom_components`, `javascript_tool`,
`capture_visual_frame`) then pass the saved JSON to `clone_website`.

`ghidra` and `app_re` are opt-in BYO. They return `unsupported` when the engine
is missing. They never execute the target binary.

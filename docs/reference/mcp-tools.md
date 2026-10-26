# MCP tools

**Spec ID:** CL4b

Thin catalog, stdio, Content-Length JSON-RPC:

`doctor` `identify` `inventory` `slice` `session_show` `evidence_get` `clone_website`

Start: `reveng-debug mcp`. This is not REA’s 207-tool catalog.

Live website capture is **not** implemented inside this process. Agents use the
gotcontext-chrome MCP (`tabs_context_mcp`, `navigate`, `extract_design_tokens`,
`tab_page_assets`, `decompose_dom_components`, `javascript_tool`,
`capture_visual_frame`) then pass the saved JSON to `clone_website`.

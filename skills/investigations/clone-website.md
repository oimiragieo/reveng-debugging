# Clone a website (SPEC-RD-007)

REA's "Clone this website" prompt, wired to **gotcontext-chrome** instead of REA CDP.

Authorized sites only. Visible structure, tokens, assets, component skeletons.
Out of scope: real backends, auth cookies, payment flows, bypassing access controls.

```
Inspect the authorized URL. Capture the live DOM with gotcontext-chrome
(tabs_context_mcp → tabs_create_mcp → navigate → get_page_text,
extract_design_tokens, tab_page_assets, decompose_dom_components,
javascript_tool outerHTML, capture_visual_frame). Save capture.json with
kind=website-capture and backend=gotcontext-chrome. Then run
reveng-debug clone-website capture.json and rebuild from the clone package
using reconstruction.md. Label every claim seen, inferred, or unknown.
```

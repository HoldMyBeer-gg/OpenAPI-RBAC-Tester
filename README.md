# OpenAPI-RBAC-Tester

An alternative Burp Suite extension for loading OpenAPI specifications and bridging parsed endpoints into Scanner, Repeater, and Intruder — with a built-in **RBAC comparison grid** for testing authorization across multiple identities in a single pass.

Offers a different feature set to the existing OpenAPI Parser extension — not a replacement.

![Main panel — spec loaded, five identities configured, session cookie imported, endpoints listed](docs/screenshots/main-panel.png)

## The RBAC differentiator

Pick any subset of endpoints, right-click → **Compare across identities…**, and the extension runs each request under each named identity you've configured. The resulting live-updating matrix classifies every row by how far each identity got through the server's processing stack — surfacing authorization anomalies that would otherwise hide under generic "403" or "404" responses.

![RBAC comparison grid showing 130 endpoints × 5 identities, 650/650 cells completed in 110 seconds](docs/screenshots/rbac-comparison.png)

Classification uses a stack-depth model rather than a plain allow/deny split:

- **Consistent allow** (green) — every identity got a 2xx. Endpoint is effectively public or tiering is broken open.
- **Consistent deny** (grey) — every identity hit the same wall. The resource may not exist for anyone, or everyone is blocked.
- **Tiered** (light green) — higher-privilege identities reached further through the stack than lower-privilege ones. Healthy role separation, including subtler patterns like `403, 403, 404` where only admin passed auth.
- **Divergent** (red) — a lower-privilege identity got further than a higher-privilege one. Possible authorization inversion.
- **Possible IDOR** (orange) — vertical tiering looks fine, but two authenticated identities got byte-identical 2xx bodies for an object-scoped endpoint (one with a path parameter). If each identity should only see its own objects, that's a horizontal escalation. Anonymous identities are ignored for this check, since "everyone sees the same thing" is public, not IDOR.

Right-click any cell to send that exact `(endpoint, identity)` request to Repeater. Export the full matrix to CSV — with a human-readable explanation column — for reporting. Declare tag→tier rules (e.g. `Admin -> admin*`) to overlay violation assessments directly in the grid and CSV.

Destructive endpoints (`/logout`, `DELETE`, `/revoke`, etc.) are detected before the run starts and offered for exclusion by default — firing `/api/logout` mid-comparison invalidates the sessions you're testing with, which the tool gracefully refuses to do silently.

## Loading a spec

Multiple ways in:

- **Drag and drop** a JSON/YAML file onto the drop zone.
- **Paste a URL or file path**, optionally filling Extra Headers with any auth the spec endpoint requires, then click Load.
- **Right-click any request in Proxy / Repeater / Logger → Send to OpenAPI-RBAC-Tester.** This is the fast path: host, base URL, and auth headers (cookies, bearer, API keys minus browser noise) are auto-imported. If the response body is an OpenAPI spec, it's auto-parsed — one click from "I have a working browser session" to a parsed endpoint list. If it isn't but the host suggests a spec (`/openapi.json`, `/swagger.json`, `/v3/api-docs`), the URL field pre-fills so Load is a single click.
- **Paste raw spec text** into the textarea and hit Parse.

When multiple identities exist, "Send to OpenAPI-RBAC-Tester" prompts for which identity should receive the imported auth — preventing silent overwrites that were a source of false-negative RBAC results.

Supports **OpenAPI 2.0 (Swagger) and OpenAPI 3.x** in both JSON and YAML. Handles the common shell-prompt paste (strips leading `anon@host:/$ cat openapi.json` chatter). Path parameters get format-aware placeholders based on the spec's schema: `format: uuid` → a real UUID, `format: date-time` → a valid ISO timestamp, enums use their first value, etc. Strict server-side validators therefore route the request to the auth layer instead of bouncing it at the URL-match stage.

## Authentication and identities

The extension centres on **named identities**. Each identity holds:

- **Bearer token** (whitespace/newlines stripped automatically for multi-line JWT paste).
- **API key** — value, header name, and location (header / query / cookie).
- **HTTP Basic** — user + password.
- **Extra headers** — free-form textarea for anything else (`Cookie:`, `X-Tenant:`, `X-CSRF-Token:`, whatever). Overrides the above on collision, so you can paste raw headers verbatim from a working request.
- **Base URL override** — per-identity, so "admin on staging" and "user on prod" stay straight.

Switch via the dropdown in the Authentication panel; **New…** / **Rename…** / **Delete** alongside it manage the named identities. Identities **persist across Burp restarts** via the Java preferences store.

When a spec declares `components.securitySchemes`, the panel shows a one-line summary and pre-fills the API key header name if exactly one `apiKey` scheme is declared.

## Sending to Burp tools

Select one or more endpoints, then use the buttons above the table (or right-click → **OpenAPI-RBAC-Tester**):

- **Actively Scan** (Pro only) — sends to Scanner with your active identity's auth. Pre-checks scope and aborts with a clear message if all selected endpoints are out of scope (Scanner otherwise silently drops them). Fires a single audit task for the whole batch.
- **Send to Repeater** — one tab per endpoint, named `METHOD /path`.
- **Send to Intruder** — auto-marks URL, cookie, and body parameter values as insertion points. Auth headers are not marked, so your session cookie / bearer token don't get overwritten by fuzz payloads.
- **Compare across identities…** — the RBAC grid. A reorderable picker lets you choose which identities to run against and set their priority order (least-privileged at top, most at bottom). Destructive endpoints in your selection are flagged and offered for exclusion.

Ctrl+I / Cmd+I sends the selection to Intruder.

## Usability details

- **Sortable columns** on the endpoint table — click any header. `#` sorts numerically (not `1, 10, 11, 2`).
- **Regex filter** (case-sensitive, capped at 500 chars to mitigate ReDoS). Live row counter.
- **Live request preview** updates when you select an endpoint or change auth fields, showing exactly what will be sent.
- **Double-click (or Space)** toggles identity inclusion in the comparison picker; single-click just selects so you can reorder with Move Up / Down without toggling as a side effect.

## Installation

1. Build: `./gradlew build`
2. In Burp: **Extensions → Installed → Add → Extension type: Java →** select `build/libs/OpenAPI-RBAC-Tester-1.0.jar`.

Requires Burp Suite with Montoya support. Active Scan requires Burp Suite Professional; everything else (RBAC comparison, imports, Intruder, Repeater) works on Community.

## Build

```bash
./gradlew build
```

Requires Java 17+. Runs the full JUnit 5 suite, Cucumber BDD scenarios, and JaCoCo coverage verification (80% line coverage gate on non-UI classes).

## License

MIT. See [LICENSE](LICENSE).

# Cursor Real Prompt Capture Fix (Apr 5, 2026)

## Goal
Make Cursor/Windsurf gateway capture stable so the tool logs the **actual user chat prompt** instead of:
- Cursor system scaffold
- open-files context wrappers
- placeholder tokens like `<user_query>`
- assistant fallback/error text

## Files Updated
- `scripts/ide_local_helper.py`

## What Changed
1. Added stronger system/scaffold detection
- Expanded system prompt markers for Cursor-specific wrappers.
- Added assistant-reply markers to avoid logging assistant boilerplate as user prompt.

2. Added embedded user-query extraction
- New embedded extraction for:
  - `<user_query>...</user_query>`
  - `<user_message>...</user_message>`
  - `<prompt>...</prompt>`
  - `User: ...` / `Prompt: ...` / `Question: ...`
- Uses last valid match as user intent.

3. Improved sanitization pipeline
- Drops system-role dict lines (`"role": "system"` / `'role': 'system'`).
- Drops explicit `system:` / `assistant:` prefixed lines.
- Rejects placeholder-only tokens.
- Prefers latest non-wrapper user-intent line.

4. Improved role handling
- Treats `user`, `human`, `end_user`, `client` as user roles.
- If role is not user but payload embeds `<user_query>...</user_query>`, still extracts and uses it.

## Expected Result
When Cursor chat is routed through the local helper + gateway:
- Requests page should show the real typed prompt (e.g., `CURSOR_LIVE_TEST_9600 hi`).
- System-context blobs and internal wrappers should no longer dominate prompt logs.

## Runtime Checklist
1. Start helper (keep this terminal open):
```bash
cd "/Users/snarayanan/Documents/AI Security/ai_security_monitoring_tool"
python3 scripts/ide_local_helper.py \
  --connector-key "<LATEST_CONNECTOR_KEY>" \
  --source "cursor-ide" \
  --provider "openai" \
  --ide-name "cursor" \
  --listen-port 12345
```

2. Cursor Base URL:
- `http://127.0.0.1:12345/v1`

3. Send a test in Cursor chat:
- `CURSOR_LIVE_TEST_9700 hello`

4. Verify in Requests page:
- Filter `source=cursor-ide`
- Confirm prompt row contains `CURSOR_LIVE_TEST_9700 hello`

## Notes
- If helper returns "Address already in use", free the port first:
```bash
lsof -ti :12345 | xargs kill -9
```
- If Cursor can’t reach localhost directly due network guardrails, use your ngrok URL ending in `/v1`.

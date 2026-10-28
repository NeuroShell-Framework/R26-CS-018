# NeuroShell Console

ChatGPT-style web UI for the NeuroShell offensive-security workflow.

It talks to **Component 01** (`POST /execute`, port 8001), which synchronously
chains into **Component 02** (`/plan`, port 8002) and returns the full pipeline
result — user input, validated intent contracts (version1/version2), and the
ready-to-run Kali command — in one response. The UI renders that chain
reaction as chat messages.

Authentication is powered by **Supabase Auth** (email/password).

## Prerequisites

- Node.js 20+
- Backend running: C1 (8001) + C2 (8002) — from `apps\services\neuroshell-ire`:
  `.\neuroshell_run.ps1` (starts both).
- A Supabase project's **URL** and **anon key** (Project Settings → API).

## Setup

```bash
cd apps\web
npm install
Copy-Item .env.example .env   # then edit .env with your Supabase values
```

`.env`:

```env
VITE_SUPABASE_URL=https://<ref>.supabase.co
VITE_SUPABASE_ANON_KEY=<anon-key>
VITE_C1_URL=http://127.0.0.1:8001
VITE_C2_URL=http://127.0.0.1:8002
VITE_C1_API_KEY=
```

Optionally create a link-type user in Supabase Auth (Dashboard → Authentication
→ Users → Add user) to skip email confirmation, or enable
"Confirm email" off for the demo team.

## Run

```bash
npm run dev
```

Open http://127.0.0.1:5173 — sign up or sign in, then chat:

> *scan host 192.168.10.14 for open ports 80 and 443 using nmap*

Each reply shows:
- C1 / C2 status badges and latencies
- The validated **command** (with copy button)
- Collapsible JSON: C2 planner output, C1 version1 contract, C1 version2

Sessions are stored in the browser (left sidebar, auto-title from the first
message) and each maps to a `session_id` sent to C1 so its server-side context
accumulates per chat.

## Scripts

| Script | Description |
| --- | --- |
| `npm run dev` | Vite dev server on :5173 |
| `npm run build` | Type-check + production build to `dist/` |
| `npm run preview` | Serve the production build |

## Notes

- CORS is wide-open on C1/C2, so the browser calls them directly.
- The sidebar shows live C1/C2 health dots (polled every 10s).
- Supabase demo users may need the confirmation email click (or disable email
  confirmation) before the session becomes active.
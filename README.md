# cf-security-rules

A single-file CLI tool to apply custom WAF rules across all your Cloudflare zones. No enterprise plan required — it applies rules to each zone individually via the Cloudflare API.

## Rules

| Priority | Name | Action | Description |
|----------|------|--------|-------------|
| 1 | Country Block | Block | Traffic from Africa, Asia, South America, and Russia |
| 2 | Scanners | Block | Common scanner paths (`.env`, `.git`, `wp-admin`, `phpinfo.php`, etc.) |
| 3 | Misc File Scans | Block | All `.php` file requests except `/index.php` |

Rules are defined in `apply-rules.py` and can be modified directly.

## Prerequisites

- [uv](https://github.com/astral-sh/uv) (`brew install uv`)
- A Cloudflare API token with:
  - **Zone.Zone**: Read
  - **Zone.WAF**: Edit
  - Zone Resources: **All zones**

Create a token at https://dash.cloudflare.com/profile/api-tokens

## Setup

```bash
cp .env.example .env
# Add your API token to .env
```

## Usage

```bash
# Apply to all zones
uv run apply-rules.py --all

# Apply to specific domains
uv run apply-rules.py --domains example.com,mysite.org

# Interactive zone picker
uv run apply-rules.py

# Dry run (no changes made)
uv run apply-rules.py --all --dry-run
```

## Notes

- Running this **replaces all existing custom WAF rules** on the target zones. This is by design — the script is the source of truth.
- Safe to re-run at any time (idempotent). Run it again when you add a new site to Cloudflare.

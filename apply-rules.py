# /// script
# dependencies = ["httpx"]
# requires-python = ">=3.10"
# ///

import httpx
import os
import sys

CF_API = "https://api.cloudflare.com/client/v4"
PHASE = "http_request_firewall_custom"

RULES = [
    {
        "description": "Country Block",
        "expression": '(ip.src.continent eq "AF") or (ip.src.continent eq "AS") or (ip.src.continent eq "SA") or (ip.src.country eq "RU")',
        "action": "block",
    },
    {
        "description": "Scanners",
        "expression": '(http.request.uri.path contains "/.env") or (http.request.uri.path contains "/.git") or (http.request.uri.path contains "/.config") or (http.request.uri.path contains "/wp-config") or (http.request.uri.path contains "/debugbar") or (http.request.uri.path contains "/wp-includes") or (http.request.uri.path contains "/wp-admin") or (http.request.uri.path contains "/wp-content") or (http.request.uri.path contains "/phpinfo.php") or (http.request.uri.path contains "/.svn") or (http.request.uri.path contains "/product")',
        "action": "block",
    },
    {
        "description": "Misc File Scans",
        "expression": '(http.request.uri.path contains ".php" and not http.request.uri.path contains "/index.php")',
        "action": "block",
    },
]


def get_token() -> str:
    token = os.environ.get("CF_API_TOKEN")
    if token:
        return token
    env_file = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(env_file):
        for line in open(env_file):
            line = line.strip()
            if line.startswith("CF_API_TOKEN="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    print("Error: CF_API_TOKEN not found. Set it as an env var or in a .env file.")
    sys.exit(1)


def get_zones(client: httpx.Client) -> list[dict]:
    zones = []
    page = 1
    while True:
        resp = client.get(f"{CF_API}/zones", params={"page": page, "per_page": 50})
        data = resp.json()
        if not data["success"]:
            print(f"Error fetching zones: {data['errors']}")
            sys.exit(1)
        zones.extend(data["result"])
        if page >= data["result_info"]["total_pages"]:
            break
        page += 1
    return zones


def select_zones(zones: list[dict], args: list[str]) -> list[dict]:
    if "--all" in args:
        return zones

    # --domains flag
    for i, arg in enumerate(args):
        if arg == "--domains" and i + 1 < len(args):
            names = [d.strip() for d in args[i + 1].split(",")]
            selected = [z for z in zones if z["name"] in names]
            missing = set(names) - {z["name"] for z in selected}
            if missing:
                print(f"Warning: zones not found: {', '.join(missing)}")
            return selected

    # Interactive selection
    print(f"\nFound {len(zones)} zones:\n")
    for i, z in enumerate(zones, 1):
        print(f"  {i}. {z['name']}")
    print()
    choice = input('Enter zone numbers (e.g. 1,3,5) or "all": ').strip()
    if choice.lower() == "all":
        return zones
    try:
        indices = [int(x.strip()) - 1 for x in choice.split(",")]
        return [zones[i] for i in indices]
    except (ValueError, IndexError):
        print("Invalid selection.")
        sys.exit(1)


def apply_rules(client: httpx.Client, zone_id: str, zone_name: str, dry_run: bool = False) -> bool:
    payload = {
        "rules": [
            {
                "description": rule["description"],
                "expression": rule["expression"],
                "action": rule["action"],
                "enabled": True,
            }
            for rule in RULES
        ],
    }
    if dry_run:
        print(f"  {zone_name}: would apply {len(payload['rules'])} rules (dry run)")
        return True

    resp = client.put(
        f"{CF_API}/zones/{zone_id}/rulesets/phases/{PHASE}/entrypoint",
        json=payload,
    )
    data = resp.json()
    if data["success"]:
        count = len(data["result"]["rules"])
        print(f"  {zone_name}: applied {count} rules")
        return True
    else:
        print(f"  {zone_name}: FAILED - {data['errors']}")
        return False


def main():
    token = get_token()
    client = httpx.Client(
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
    )

    zones = get_zones(client)
    if not zones:
        print("No zones found in your account.")
        sys.exit(1)

    args = sys.argv[1:]
    dry_run = "--dry-run" in args

    selected = select_zones(zones, args)
    if not selected:
        print("No zones selected.")
        sys.exit(0)

    mode = "DRY RUN" if dry_run else "LIVE"
    print(f"\n[{mode}] Applying {len(RULES)} rules to {len(selected)} zone(s)...\n")
    print("Rules:")
    for r in RULES:
        print(f"  - {r['description']} [{r['action']}]")
    print()

    ok = 0
    for zone in selected:
        if apply_rules(client, zone["id"], zone["name"], dry_run=dry_run):
            ok += 1

    print(f"\nDone: {ok}/{len(selected)} zones ({mode}).")


if __name__ == "__main__":
    main()

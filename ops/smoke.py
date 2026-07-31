"""HTTP smoke checks for staging and production go-live gates."""
import json
import sys
import urllib.error
import urllib.request


def _get(base: str, path: str) -> tuple[int, bytes]:
    req = urllib.request.Request(f"{base.rstrip('/')}{path}", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310 - operator-supplied base URL
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def _post_json(base: str, path: str, payload: dict, headers: dict | None = None) -> tuple[int, bytes]:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"{base.rstrip('/')}{path}",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def run_smoke(*, base_url: str) -> list[str]:
    failures: list[str] = []
    try:
        status, _ = _get(base_url, "/readyz")
    except OSError as exc:
        failures.append(f"could not reach {base_url}: {exc}")
        return failures
    if status != 200:
        failures.append(f"/readyz expected 200, got {status}")
    try:
        status, body = _get(base_url, "/api/v1/auth/status/")
    except OSError as exc:
        failures.append(f"auth/status unreachable: {exc}")
        return failures
    if status != 200:
        failures.append(f"/api/v1/auth/status/ expected 200, got {status}")
    else:
        try:
            payload = json.loads(body.decode())
        except json.JSONDecodeError:
            failures.append("auth/status returned non-JSON")
            payload = None
        if payload is not None and payload.get("authenticated") not in (True, False):
            failures.append("auth/status missing authenticated flag")
    try:
        status, _ = _post_json(base_url, "/api/v1/auth/login/", {"username": "nobody", "password": "wrong"})
    except OSError as exc:
        failures.append(f"auth/login unreachable: {exc}")
        return failures
    if status not in (401, 429):
        failures.append(f"auth/login with bad creds expected 401/429, got {status}")
    return failures

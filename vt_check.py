from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict

import requests


VT_BASE = "https://www.virustotal.com/api/v3"


def fetch_file_report(api_key: str, file_hash: str) -> Dict[str, Any]:
    url = f"{VT_BASE}/files/{file_hash}"
    headers = {"x-apikey": api_key}
    resp = requests.get(url, headers=headers, timeout=30)

    # Понятные ошибки
    if resp.status_code == 401:
        raise RuntimeError("401 Unauthorized: проверь VT_API_KEY (неверный/пустой ключ).")
    if resp.status_code == 404:
        raise RuntimeError("404 Not Found: VirusTotal не знает этот хэш (файл не встречался).")
    if resp.status_code == 429:
        raise RuntimeError("429 Too Many Requests: лимит запросов (подожди и повтори).")
    if not resp.ok:
        raise RuntimeError(f"Ошибка API: HTTP {resp.status_code}, ответ: {resp.text[:300]}")

    return resp.json()


def print_summary(data: Dict[str, Any]) -> None:
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    md5 = attrs.get("md5", "n/a")
    sha1 = attrs.get("sha1", "n/a")
    sha256 = attrs.get("sha256", "n/a")

    print("\n=== Краткая сводка ===")
    print(f"md5:    {md5}")
    print(f"sha1:   {sha1}")
    print(f"sha256: {sha256}")
    print("\nlast_analysis_stats:")
    for k in ["malicious", "suspicious", "undetected", "harmless", "timeout"]:
        if k in stats:
            print(f"  {k:11s}: {stats[k]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="VirusTotal API v3: report by SHA-256 hash")
    parser.add_argument("--hash", required=True, help="SHA-256 хэш файла (64 hex символа)")
    parser.add_argument("--out", default="response.json", help="Имя файла для сохранения JSON")
    args = parser.parse_args()

    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("Не задана переменная окружения VT_API_KEY.", file=sys.stderr)
        print('Задай так: setx VT_API_KEY "ВАШ_КЛЮЧ"  (потом перезапусти терминал)', file=sys.stderr)
        return 2

    file_hash = args.hash.strip()

    try:
        data = fetch_file_report(api_key, file_hash)
    except Exception as e:
        print(f"Ошибка: {e}", file=sys.stderr)
        return 1

    # 1) Вывод JSON в консоль (сокращать не будем — по требованиям можно полностью)
    print("\n=== Полный JSON-ответ ===")
    print(json.dumps(data, ensure_ascii=False, indent=2))

    # 2) Сводка (удобно для проверки)
    print_summary(data)

    # 3) Сохранение в файл
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"\nJSON сохранён в файл: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
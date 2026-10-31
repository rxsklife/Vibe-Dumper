                    "error": "scan_error",
                    "jwt_count": 0,
                    "supabase_urls": [],
                    "sensitive_indicators": [],
                })

    return sorted(results, key=lambda item: item["url"])


def scan_site(site_url, max_js=100, workers=8):
    """Passive, same-origin review. Does not query database tables or dump records."""
    site_url = normalize_url(site_url)
    safe_print(f"[*] Target: {site_url}")

    response = safe_get(site_url, headers=COMMON_HEADERS, allow_redirects=False)
    if response is None:
        raise RuntimeError("Could not retrieve the target page")

    if response.status_code >= 400:
        raise RuntimeError(f"Target returned HTTP {response.status_code}")

    html = response.text[:5_000_000]
    html_supabase = extract_supabase_urls(html)
    html_jwts = JWT_REGEX.findall(html)

    js_files = get_js_files(site_url, max_files=max_js)
    safe_print(f"[*] Discovered {len(js_files)} same-origin JavaScript files")

    js_results = scan_js_files_parallel(js_files, workers=workers)
    all_supabase = set(html_supabase)
    total_jwts = len(html_jwts)
    indicators = set()

    for result in js_results:
        all_supabase.update(result.get("supabase_urls", []))
        total_jwts += result.get("jwt_count", 0)
        indicators.update(result.get("sensitive_indicators", []))

    return {
        "target": site_url,
        "http_status": response.status_code,
        "scanned_at_utc": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "javascript_files_discovered": len(js_files),
        "javascript_files_scanned": sum(
            1 for result in js_results if result.get("error") is None
        ),
        "jwt_occurrences": total_jwts,
        "supabase_projects": sorted(all_supabase),
        "sensitive_content_indicators": sorted(indicators),
        "javascript_results": js_results,
        "scope": "same-origin passive inspection; no database records requested",
    }


def write_report(report, output_dir=OUTPUT_DIR):
    os.makedirs(output_dir, exist_ok=True)
    host = urlparse(report["target"]).hostname or "target"
    safe_host = re.sub(r"[^A-Za-z0-9._-]", "_", host)
    filename = os.path.join(output_dir, f"{safe_host}_audit.json")

    # Report contains URLs and indicator names, never raw JWT values.
    temp_name = filename + ".tmp"
    with open(temp_name, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
    os.replace(temp_name, filename)
    return filename


def build_parser():
    parser = argparse.ArgumentParser(
        description="VibeDumper - passive website/Supabase configuration auditor"
    )
    parser.add_argument(
        "url",
        help="Website URL you own or are explicitly authorized to assess"
    )
    parser.add_argument(
        "--max-js", type=int, default=100,
        help="Maximum same-origin JavaScript files to inspect (default: 100)"
    )
    parser.add_argument(
        "--workers", type=int, default=8,
        help="Concurrent requests (default: 8; maximum: 12)"
    )
    parser.add_argument(
        "--output", default=OUTPUT_DIR,
        help=f"Report directory (default: {OUTPUT_DIR})"
    )
    parser.add_argument(
        "--no-report", action="store_true",
        help="Print summary without writing a JSON report"
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.max_js < 1 or args.max_js > 500:
        parser.error("--max-js must be between 1 and 500")
    if args.workers < 1 or args.workers > 12:
        parser.error("--workers must be between 1 and 12")

    try:
        report = scan_site(args.url, max_js=args.max_js, workers=args.workers)
        print("\n=== VIBEDUMPER AUDIT SUMMARY ===")
        print(f"Target: {report['target']}")
        print(f"HTTP status: {report['http_status']}")
        print(
            "JavaScript files: "
            f"{report['javascript_files_scanned']}/"
            f"{report['javascript_files_discovered']}"
        )
        print(f"JWT occurrences: {report['jwt_occurrences']}")
        print(f"Supabase project URLs: {len(report['supabase_projects'])}")
        for project_url in report["supabase_projects"]:
            print(f"  - {project_url}")
        print(
            "Sensitive-content indicators: "
            + (", ".join(report["sensitive_content_indicators"]) or "none")
        )
        print("\n[!] JWT values and data records are intentionally not displayed.")

        if not args.no_report:
            report_path = write_report(report, args.output)
            print(f"[+] Report saved: {report_path}")

        return 0

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted")
        return 130
    except (ValueError, RuntimeError, OSError) as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[!] Unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

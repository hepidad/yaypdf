#!/usr/bin/env python3
"""
Download all PDFs found on a page (optionally crawling subpages).

Examples:
  python download_pdfs.py "https://example.com/resources"
  python download_pdfs.py "https://example.com" --depth 2 --same-domain --out pdfs --concurrency 8

Notes:
- Respect site terms/robots. Add --delay if you're crawling.
- For login-protected PDFs, you'll need cookies/headers (see --header).
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import hashlib
import os
import re
import sys
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urldefrag

import requests
from bs4 import BeautifulSoup


PDF_CT = "application/pdf"
HTML_CT = "text/html"


@dataclass(frozen=True)
class Link:
    url: str
    where: str


def normalize_url(u: str) -> str:
    # Drop fragments (#...) and trim whitespace
    u = u.strip()
    u, _frag = urldefrag(u)
    return u


def same_domain(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def is_likely_pdf_url(u: str) -> bool:
    p = urlparse(u)
    path = p.path.lower()
    # common patterns: .pdf or .pdf?download=1
    if path.endswith(".pdf"):
        return True
    if ".pdf" in path:
        return True
    # sometimes URLs don't show extension but contain hints
    if "pdf" in (p.path.lower() + " " + (p.query or "").lower()):
        return True
    return False


def guess_filename_from_headers(url: str, r: requests.Response) -> str:
    cd = r.headers.get("Content-Disposition", "")
    # naive but useful: filename="..."
    m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd, re.IGNORECASE)
    if m:
        name = m.group(1).strip()
        return sanitize_filename(name)

    # fall back to URL path
    path = urlparse(url).path
    base = os.path.basename(path) or ""
    if base:
        return sanitize_filename(base)

    # last resort: hash
    h = hashlib.sha1(url.encode("utf-8")).hexdigest()[:12]
    return f"file-{h}.pdf"


def sanitize_filename(name: str) -> str:
    # keep it filesystem-friendly
    name = name.strip().strip(".")
    name = name.replace("\\", "_").replace("/", "_")
    name = re.sub(r"[\x00-\x1f<>:\"|?*]+", "_", name)
    if not name.lower().endswith(".pdf"):
        name += ".pdf"
    if not name:
        name = "file.pdf"
    return name


def unique_path(out_dir: Path, filename: str) -> Path:
    p = out_dir / filename
    if not p.exists():
        return p
    stem = p.stem
    suffix = p.suffix
    for i in range(2, 10_000):
        candidate = out_dir / f"{stem} ({i}){suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError(f"Too many filename collisions for {filename}")


def extract_links(html: str, base_url: str) -> Tuple[Set[Link], Set[str]]:
    """
    Returns:
      pdf_candidates: set of Link(url, where)
      page_candidates: set of URLs that look like HTML pages to crawl
    """
    soup = BeautifulSoup(html, "html.parser")

    pdfs: Set[Link] = set()
    pages: Set[str] = set()

    # attrs to check across tags
    tag_attr = [
        ("a", "href"),
        ("link", "href"),
        ("iframe", "src"),
        ("embed", "src"),
        ("object", "data"),
        ("source", "src"),
    ]

    for tag, attr in tag_attr:
        for el in soup.find_all(tag):
            raw = el.get(attr)
            if not raw:
                continue
            abs_url = normalize_url(urljoin(base_url, raw))
            if not abs_url.startswith(("http://", "https://")):
                continue

            if is_likely_pdf_url(abs_url):
                pdfs.add(Link(abs_url, f"{tag}[{attr}]"))
            else:
                # treat as a page candidate if it looks like a navigable HTML doc
                # (no extension or common html endings)
                path = urlparse(abs_url).path.lower()
                ext = os.path.splitext(path)[1]
                if ext in ("", ".html", ".htm", ".php", ".asp", ".aspx", ".jsp"):
                    pages.add(abs_url)

    return pdfs, pages


def head_content_type(session: requests.Session, url: str, timeout: int) -> Optional[str]:
    try:
        r = session.head(url, allow_redirects=True, timeout=timeout)
        ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        return ct or None
    except requests.RequestException:
        return None


def download_pdf(session: requests.Session, url: str, out_dir: Path, timeout: int) -> Tuple[str, Optional[Path], str]:
    """
    Returns (url, saved_path_or_None, status_msg)
    """
    try:
        with session.get(url, stream=True, allow_redirects=True, timeout=timeout) as r:
            r.raise_for_status()
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()

            if ct and ct != PDF_CT:
                # Sometimes servers lie, but let's be conservative
                # If URL endswith .pdf, still allow; otherwise skip
                if not urlparse(url).path.lower().endswith(".pdf"):
                    return url, None, f"SKIP (content-type={ct})"

            filename = guess_filename_from_headers(url, r)
            out_path = unique_path(out_dir, filename)

            out_dir.mkdir(parents=True, exist_ok=True)
            with open(out_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=1024 * 128):
                    if chunk:
                        f.write(chunk)

            return url, out_path, "OK"
    except requests.RequestException as e:
        return url, None, f"ERROR ({e.__class__.__name__}: {e})"


def build_session(headers: list[str], timeout: int) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "pdf-downloader/1.0 (+https://example.invalid) requests"
    })
    for h in headers:
        if ":" not in h:
            raise ValueError(f"Invalid header format: {h!r} (use 'Key: Value')")
        k, v = h.split(":", 1)
        s.headers[k.strip()] = v.strip()
    # timeout is passed per request; kept here for consistency
    return s


def crawl_and_collect(
    session: requests.Session,
    start_url: str,
    depth: int,
    same_domain_only: bool,
    delay: float,
    timeout: int,
    verify_pdf_by_head: bool,
) -> Set[str]:
    start_url = normalize_url(start_url)
    seen_pages: Set[str] = set()
    found_pdfs: Set[str] = set()

    q = deque([(start_url, 0)])

    while q:
        page_url, d = q.popleft()
        if page_url in seen_pages:
            continue
        seen_pages.add(page_url)

        if same_domain_only and not same_domain(start_url, page_url):
            continue

        try:
            r = session.get(page_url, timeout=timeout)
            r.raise_for_status()
            ct = (r.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            if ct and ct != HTML_CT and "html" not in ct:
                continue  # not an HTML page
        except requests.RequestException:
            continue

        pdf_candidates, page_candidates = extract_links(r.text, page_url)

        # add pdfs
        for link in pdf_candidates:
            u = link.url
            if u in found_pdfs:
                continue

            if verify_pdf_by_head and not urlparse(u).path.lower().endswith(".pdf"):
                ct = head_content_type(session, u, timeout=timeout)
                if ct and ct != PDF_CT:
                    continue

            found_pdfs.add(u)

        # crawl deeper pages
        if d < depth:
            for u in page_candidates:
                if same_domain_only and not same_domain(start_url, u):
                    continue
                if u not in seen_pages:
                    q.append((u, d + 1))

        if delay > 0:
            time.sleep(delay)

    return found_pdfs


def main():
    ap = argparse.ArgumentParser(description="Download all PDFs found on a URL (optionally crawling subpages).")
    ap.add_argument("url", help="Starting page URL")
    ap.add_argument("--out", default="downloaded_pdfs", help="Output directory (default: downloaded_pdfs)")
    ap.add_argument("--depth", type=int, default=0, help="Crawl depth (0 = only the given page)")
    ap.add_argument("--same-domain", action="store_true", help="Only crawl/download within the starting domain")
    ap.add_argument("--concurrency", type=int, default=6, help="Parallel downloads (default: 6)")
    ap.add_argument("--delay", type=float, default=0.0, help="Delay between page fetches (seconds)")
    ap.add_argument("--timeout", type=int, default=25, help="Request timeout in seconds (default: 25)")
    ap.add_argument("--verify-by-head", action="store_true",
                    help="For non-.pdf URLs, HEAD-check content-type before downloading")
    ap.add_argument("--header", action="append", default=[],
                    help="Extra HTTP header, repeatable. Example: --header 'Cookie: a=b' --header 'Authorization: Bearer ...'")

    args = ap.parse_args()

    out_dir = Path(args.out)
    session = build_session(args.header, timeout=args.timeout)

    pdf_urls = crawl_and_collect(
        session=session,
        start_url=args.url,
        depth=max(0, args.depth),
        same_domain_only=args.same_domain,
        delay=max(0.0, args.delay),
        timeout=args.timeout,
        verify_pdf_by_head=args.verify_by_head,
    )

    if not pdf_urls:
        print("No PDFs found.")
        return 0

    print(f"Found {len(pdf_urls)} PDF(s). Downloading to: {out_dir.resolve()}")

    ok = 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futures = [ex.submit(download_pdf, session, u, out_dir, args.timeout) for u in sorted(pdf_urls)]
        for fut in cf.as_completed(futures):
            url, saved, status = fut.result()
            if saved:
                ok += 1
                print(f"[OK]   {saved.name}  <=  {url}")
            else:
                print(f"[{status}] {url}")

    print(f"Done. Downloaded {ok}/{len(pdf_urls)}.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

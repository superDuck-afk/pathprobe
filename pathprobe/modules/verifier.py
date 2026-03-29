"""Re-verification of findings — reduce false positives.

Re-sends the triggering payload multiple times with staggered delays
and confirms that the result is consistent before marking as verified.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from pathprobe.core.types import Finding, PayloadMeta, Response
from pathprobe.core import config
from pathprobe.modules import response_analyzer


async def verify_finding_async(
    transport,        # AsyncTransport instance
    url: str,
    param: str,
    payload: str,
    method: str,
    baseline: Response,
    payload_meta: Optional[PayloadMeta] = None,
    post_mode: Optional[str] = None,
    post_builder=None,
    extra_headers: Optional[dict] = None,
    cookies: Optional[str] = None,
    verify_count: int = config.VERIFY_COUNT,
    delay: float = config.VERIFY_DELAY_S,
) -> tuple[bool, bool, int]:
    """Re-send the payload *verify_count* times and check consistency.

    Returns ``(confirmed, consistent, attempts)``.

    - ``confirmed``: all re-verification attempts also triggered
    - ``consistent``: the same signatures fired every time
    """
    sig_sets = []
    all_vulnerable = True

    for i in range(verify_count):
        if i > 0:
            await asyncio.sleep(delay)

        if method == "GET":
            resp = await transport.get(
                url, param=param, payload=payload,
                extra_headers=extra_headers, cookies=cookies,
            )
        else:
            body, ph = post_builder(param, payload)
            merged_h = dict(extra_headers or {})
            merged_h.update(ph)
            resp = await transport.post(
                url, data=body, extra_headers=merged_h, cookies=cookies,
            )

        if resp is None:
            all_vulnerable = False
            sig_sets.append(frozenset())
            continue

        result = response_analyzer.analyse(resp, baseline, payload_meta)
        if not result.vulnerable:
            all_vulnerable = False
        sig_sets.append(
            frozenset(m.signature for m in result.matches)
        )

    confirmed = all_vulnerable
    consistent = len(set(sig_sets)) <= 1 and len(sig_sets) == verify_count

    return confirmed, consistent, verify_count

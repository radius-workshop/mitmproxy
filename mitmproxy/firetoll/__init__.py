"""Firetoll: process attribution, traffic classification, a session store,
and a CLI report - making mitmproxy's traffic legible to an agent.

Everything lives in this package so the upstream diff stays small; see the
repository README and AGENTS.md for shipped behavior and development rules.
"""

from mitmproxy.firetoll import attribution
from mitmproxy.firetoll import enrich
from mitmproxy.firetoll import options
from mitmproxy.firetoll import report
from mitmproxy.firetoll import store


def firetoll_addons() -> list:
    store_addon = store.FiretollStore()
    return [
        options.FiretollOptions(),
        attribution.Attribution(),
        enrich.Enrich(store_addon),
        # report must precede store in the chain: `done` hooks fire in chain
        # order, and the report needs to read the store before it closes.
        report.FiretollReport(store_addon),
        store_addon,
    ]

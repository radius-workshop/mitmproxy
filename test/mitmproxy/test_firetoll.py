from mitmproxy import firetoll
from mitmproxy.firetoll.attribution import Attribution
from mitmproxy.firetoll.enrich import Enrich
from mitmproxy.firetoll.options import FiretollOptions
from mitmproxy.firetoll.report import FiretollReport
from mitmproxy.firetoll.store import FiretollStore


class TestFiretollAddons:
    def test_returns_addons_in_wiring_order(self):
        addons = firetoll.firetoll_addons()

        assert len(addons) == 5
        assert isinstance(addons[0], FiretollOptions)
        assert isinstance(addons[1], Attribution)
        assert isinstance(addons[2], Enrich)
        # report must precede store in the chain: `done` hooks fire in chain
        # order, and the report needs to read the store before it closes.
        assert isinstance(addons[3], FiretollReport)
        assert isinstance(addons[4], FiretollStore)

        # enrich, report, and the trailing store addon all share the same
        # store instance.
        store_addon = addons[4]
        assert addons[2].store_addon is store_addon
        assert addons[3].store_addon is store_addon

from mitmproxy.firetoll.classify import botdetect
from mitmproxy.test import tflow
from mitmproxy.test import tutils


def _flow(status=200, resp_headers=None, resp_content=b"", **req_kwargs):
    req_kwargs.setdefault("host", "example.com")
    req_kwargs.setdefault("path", "/")
    return tflow.tflow(
        req=tutils.treq(**req_kwargs),
        resp=tutils.tresp(
            status_code=status, headers=resp_headers or [], content=resp_content
        ),
    )


class TestCloudflareDetection:
    def test_cf_mitigated_header(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(status=403, resp_headers=[(b"cf-mitigated", b"challenge")])
        findings = [x for x in detector.detect(f) if x.cls == "botdetect"]
        assert len(findings) == 1
        assert findings[0].facts["vendor"] == "Cloudflare"
        assert findings[0].confidence == "signature"

    def test_cf_ray_with_403(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(status=403, resp_headers=[(b"cf-ray", b"abc123-SJC")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Cloudflare"

    def test_cf_ray_with_200_is_not_flagged(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(status=200, resp_headers=[(b"cf-ray", b"abc123-SJC")])
        response_findings = [
            x for x in detector.detect(f) if x.label == "Cloudflare challenge"
        ]
        assert response_findings == []

    def test_cf_chl_body_marker(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(status=200, resp_content=b"<script>window.__cf_chl_opt={}</script>")
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Cloudflare"

    def test_turnstile_body_marker(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(
            status=200,
            resp_content=b'<script src="https://challenges.cloudflare.com/turnstile/v0/api.js">',
        )
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Cloudflare Turnstile"


class TestCookieVendorDetection:
    def test_akamai_abck(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"_abck=xyz; Path=/")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Akamai Bot Manager"

    def test_akamai_bmsc(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"ak_bmsc=xyz; Path=/")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Akamai Bot Manager"

    def test_perimeterx_prefix(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"_pxvid=xyz; Path=/")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "PerimeterX"

    def test_datadome(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"datadome=xyz; Path=/")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "DataDome"

    def test_incapsula_visid(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"visid_incap_12345=xyz; Path=/")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Imperva/Incapsula"

    def test_incapsula_session(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"incap_ses_123_456=xyz; Path=/")])
        findings = detector.detect(f)
        assert findings[0].facts["vendor"] == "Imperva/Incapsula"

    def test_unrelated_cookie_no_finding(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(resp_headers=[(b"set-cookie", b"session_id=xyz; Path=/")])
        response_findings = [x for x in detector.detect(f) if "challenge" in x.label]
        assert response_findings == []


class TestRequestSideDetection:
    def test_fingerprint_script_path(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(path="/static/fp.min.js")
        findings = [x for x in detector.detect(f) if "fingerprinting" in x.label]
        assert len(findings) == 1
        assert findings[0].confidence == "heuristic"

    def test_cloudflare_challenge_platform_path(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(path="/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1")
        findings = [x for x in detector.detect(f) if "fingerprinting" in x.label]
        assert len(findings) == 1

    def test_hcaptcha_widget_host(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(host="js.hcaptcha.com", path="/1/api.js")
        findings = [x for x in detector.detect(f) if "widget load" in x.label]
        assert findings[0].facts["vendor"] == "hCaptcha"

    def test_no_match_no_finding(self):
        detector = botdetect.BotDetectDetector()
        f = _flow(host="example.com", path="/normal/page")
        assert detector.detect(f) == []


class TestTlsClientProfile:
    def test_profile_hash_is_stable(self):
        client = tflow.tclient_conn()
        client.tls_version = "TLSv1.3"
        client.sni = "example.com"
        client.alpn = b"h2"
        client.alpn_offers = (b"h2", b"http/1.1")

        profile1 = botdetect.tls_client_profile(client)
        profile2 = botdetect.tls_client_profile(client)
        assert profile1["tls_profile_hash"] == profile2["tls_profile_hash"]
        assert profile1["tls_version"] == "TLSv1.3"
        assert profile1["sni"] == "example.com"
        assert profile1["alpn_offers"] == ["h2", "http/1.1"]

    def test_different_sni_yields_different_hash(self):
        client_a = tflow.tclient_conn()
        client_a.sni = "a.example.com"
        client_b = tflow.tclient_conn()
        client_b.sni = "b.example.com"
        assert (
            botdetect.tls_client_profile(client_a)["tls_profile_hash"]
            != botdetect.tls_client_profile(client_b)["tls_profile_hash"]
        )

    def test_cipher_list_is_not_part_of_the_profile(self):
        # cipher_list reflects the proxy's own configured ciphers
        # (mitmproxy/addons/tlsconfig.py), not the client's ClientHello, so
        # changing it must not change the profile hash.
        client_a = tflow.tclient_conn()
        client_a.cipher_list = ("TLS_AES_128_GCM_SHA256",)
        client_b = tflow.tclient_conn()
        client_b.cipher_list = (
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        )
        assert (
            botdetect.tls_client_profile(client_a)["tls_profile_hash"]
            == botdetect.tls_client_profile(client_b)["tls_profile_hash"]
        )

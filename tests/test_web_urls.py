import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from surge_cc import core, web_urls


class WebURLTests(unittest.TestCase):
    def test_preserves_valid_page_query_and_fragment(self):
        values = ["https://example.com/", "https://claude.ai/artifact/fixture?q=a%20b#section",
                  "http://localhost:3000/preview", "http://127.0.0.1:8080/",
                  "http://[::1]:3000/", "https://例子.测试/文档", "HTTPS://EXAMPLE.COM./"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(web_urls.validate_url(value), value)

    def test_rejects_unsafe_schemes_authorities_controls_and_oversized_links(self):
        values = [None, 12, "", "//example.com", "file:///tmp/a", "javascript:alert(1)",
                  "chrome://newtab/", "https:///missing", "https://user:password@example.com/",
                  "https://@example.com/", "https://a%40b.example/", "http://[::1%25en0]/",
                  "https://example.com:0/", "https://example.com:65536/", "https://example.com:abc/",
                  "https://.example.com/", "https://a..b/", "https://bad_host/",
                  " https://example.com/", "https://example.com/a b", "https://example.com/\n",
                  "https://example.com/%00", "https://example.com/%0D%0a", "https://example.com/\x7f",
                  "https://example.com/%C2%85", "https://example.com/%zz", "https://example.com/%FF",
                  "https://example.com/\\a", "https://example.com/%5cfoo", "https://example.com/" + "a" * 16384]
        for value in values:
            with self.subTest(value=str(value)[:100]), self.assertRaises(core.Blocked):
                web_urls.validate_url(value)

    def test_rejection_never_echoes_link_or_its_credentials(self):
        with self.assertRaises(core.Blocked) as caught:
            web_urls.validate_url("https://user:private-test-secret@example.com/?token=private-test-token")
        self.assertNotIn("private-test", str(caught.exception))
        self.assertNotIn("example.com", str(caught.exception))


if __name__ == "__main__":
    unittest.main()

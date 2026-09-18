import ipaddress
import unittest

from app import parse_tshark, trust_analysis


class AttributionTest(unittest.TestCase):
    trusted = [ipaddress.ip_network("127.0.0.2/32")]

    def test_direct_and_spoofed_header(self):
        direct = trust_analysis("127.0.0.1", {}, self.trusted, [])
        spoof = trust_analysis("127.0.0.1", {"x-forwarded-for": "203.0.113.9"}, self.trusted, [])
        self.assertEqual((direct["classification"], direct["trusted_client"]), ("DIRECT", None))
        self.assertEqual((spoof["classification"], spoof["confidence"], spoof["trusted_client"]),
                         ("UNTRUSTED HEADER", "UNTRUSTED", None))

    def test_nearest_untrusted_hop_wins(self):
        result = trust_analysis("127.0.0.2", {"x-forwarded-for": "203.0.113.9, 198.51.100.8"}, self.trusted, [])
        self.assertEqual((result["classification"], result["trusted_client"]), ("PROXIED", "198.51.100.8"))

    def test_cloudflare_header_requires_cloudflare_peer(self):
        result = trust_analysis("127.0.0.2", {"cf-connecting-ip": "203.0.113.9"}, self.trusted, [])
        self.assertIsNone(result["trusted_client"])

    def test_tshark_syn_and_malformed_record(self):
        values = ["1789733550.917276097", "127.0.0.1", "", "45276", "", "127.0.0.1", "",
                  "18080", "", "TCP", "True", "False"]
        self.assertEqual(parse_tshark("\t".join(values))["destination_port"], 18080)
        values[-1] = "True"
        self.assertIsNone(parse_tshark("\t".join(values)))
        self.assertIsNone(parse_tshark("garbage"))


if __name__ == "__main__":
    unittest.main()

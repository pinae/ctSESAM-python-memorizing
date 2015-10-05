#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from domain_extractor import extract_top_domain, extract_full_domain


class TestDomainExtractor(unittest.TestCase):
    def test_extract_top_domain(self):
        self.assertEqual(
            "test.com",
            extract_top_domain("http://www.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_top_domain("http://test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_top_domain("http://complicated.subdomain.structure.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_top_domain("https://www.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_top_domain("https://test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_top_domain("https://complicated.subdomain.structure.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_top_domain("test.com"))
        self.assertEqual(
            "test.com",
            extract_top_domain("www.test.com"))
        self.assertEqual(
            "test.com",
            extract_top_domain("complicated.subdomain.structure.test.com"))
        self.assertEqual(
            "test.com",
            extract_top_domain("test.com/path/to/things"))
        self.assertEqual(
            "amazon.co.jp",
            extract_top_domain("www.amazon.co.jp/search=?some(characters)[strange]"))
        self.assertEqual(
            "english.co.uk",
            extract_top_domain("english.co.uk"))
        self.assertEqual(
            "noUrl",
            extract_top_domain("noUrl"))

    def test_extract_full_domain(self):
        self.assertEqual(
            "www.test.com",
            extract_full_domain("http://www.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_full_domain("http://test.com/some/path/index.html"))
        self.assertEqual(
            "complicated.subdomain.structure.test.com",
            extract_full_domain("http://complicated.subdomain.structure.test.com/some/path/index.html"))
        self.assertEqual(
            "www.test.com",
            extract_full_domain("https://www.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_full_domain("https://test.com/some/path/index.html"))
        self.assertEqual(
            "complicated.subdomain.structure.test.com",
            extract_full_domain("https://complicated.subdomain.structure.test.com/some/path/index.html"))
        self.assertEqual(
            "test.com",
            extract_full_domain("test.com"))
        self.assertEqual(
            "www.test.com",
            extract_full_domain("www.test.com"))
        self.assertEqual(
            "complicated.subdomain.structure.test.com",
            extract_full_domain("complicated.subdomain.structure.test.com"))
        self.assertEqual(
            "test.com",
            extract_full_domain("test.com/path/to/things"))
        self.assertEqual(
            "www.amazon.co.jp",
            extract_full_domain("www.amazon.co.jp/search=?some(characters)[strange]"))
        self.assertEqual(
            "english.co.uk",
            extract_full_domain("english.co.uk"))
        self.assertEqual(
            "noUrl",
            extract_full_domain("noUrl"))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from unittest.mock import patch
from sync import Sync
from base64 import b64encode
import json


class MockResponse(object):
    """
    A response with a similar format as requests.post produces.
    """
    def __init__(self, blob=''):
        self.status_code = 200
        if len(blob) > 0:
            self.text = json.dumps({
                "status": "ok",
                "result": blob
            })
        else:
            self.text = json.dumps({
                "status": "ok"
            })


def mock_requests_post_empty(url, data, headers, verify):
    """
    Returns a response with a similar format as requests.post produces.

    :param url:
    :param data:
    :param headers:
    :param verify:
    :return:
    :rtype: MockResponse
    """
    return MockResponse()


def mock_requests_post(url, data, headers, verify):
    """
    Returns a response with a similar format as requests.post produces.

    :param url:
    :param data:
    :param headers:
    :param verify:
    :return:
    :rtype: MockResponse
    """
    return MockResponse(str(b64encode(b'Test'), encoding='utf-8'))


class TestSync(unittest.TestCase):
    @patch('requests.post', mock_requests_post_empty)
    def test_pull_empty_request(self):
        sync = Sync("https://ersatzworld.net/ctpwdgen-server/", 'inter', 'op', 'file.pem')
        status, blob = sync.pull()
        self.assertTrue(status)
        self.assertEqual('', blob)

    @patch('requests.post', mock_requests_post)
    def test_pull(self):
        sync = Sync("https://ersatzworld.net/ctpwdgen-server/", 'inter', 'op', 'file.pem')
        status, blob = sync.pull()
        self.assertTrue(status)
        self.assertEqual(str(b64encode(b'Test'), encoding='utf-8'), blob)

    @patch('requests.post', mock_requests_post)
    def test_push(self):
        sync = Sync("https://ersatzworld.net/ctpwdgen-server/", 'inter', 'op', 'file.pem')
        self.assertTrue(sync.push(str(b64encode(b'Test'), encoding='utf-8')))


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Functions for extracting domains.
"""

import re


def extract_top_domain(url):
    """
    Extracts the domain from an url. Subdomains are ignored

    :param url: Url with https:// and /some/path
    :type url: str
    :return: domain name without protocol, subdomains or path
    :rtype: str
    """
    pattern = re.compile("(?:https?://)?(\w+\.)+(co\.\w+).*")
    matches = pattern.match(url)
    if matches and len(matches.groups()) >= 2:
        return matches.group(len(matches.groups()) - 1) + matches.group(len(matches.groups()))
    pattern = re.compile("(?:https?://)?(\w+\.)+(\w+).*")
    matches = pattern.match(url)
    if matches and len(matches.groups()) >= 2:
        return matches.group(len(matches.groups()) - 1) + matches.group(len(matches.groups()))
    else:
        return url


def extract_full_domain(url):
    """
    Extracts the domain from an url

    :param url: Url with https:// and /some/path
    :type url: str
    :return: domain name without protocol or path
    :rtype: str
    """
    pattern = re.compile("(?:https?://)?((?:\w+\.)*)(\w+).*")
    matches = pattern.match(url)
    if matches and len(matches.groups()) >= 2:
        return "".join(matches.groups())
    else:
        return url

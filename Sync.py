#!/usr/bin/python3
# -*- coding: utf-8 -*-

import requests
import json
import base64
import os


class Sync(object):
    """
    Sync connection wrapper.

    :param str server_url: https://my.server.domain/path/to/php/
    :param str username:
    :param str password:
    """
    def __init__(self, server_url, username, password, cert_filename):
        self.server_url = server_url
        self.username = username
        self.password = password
        self.certificate_filename = cert_filename
        self.headers = {
            'content-type': 'application/x-www-form-urlencoded',
            'Authorization': 'Basic ' + str(base64.b64encode(
                (self.username + ':' + self.password).encode('utf-8')
            ), encoding='utf-8')
        }

    def pull(self):
        """
        Read the base64 encoded data from the sync server.

        :return: base64 encoded data
        :rtype: str
        """
        request = requests.post(self.server_url + "ajax/read.php",
                                data="",
                                headers=self.headers,
                                verify=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                    self.certificate_filename))
        if request.status_code == requests.codes.ok:
            received_data = json.loads(request.text)
            if 'status' in received_data and received_data['status']:
                if 'result' in received_data:
                    return True, received_data['result']
                else:
                    return True, ''
            else:
                return False, ''
        else:
            return False, ''

    def push(self, data):
        """
        Push data to the server. This overwrites data living there. Please pull and merge first.

        :param str data: base64 encoded data
        :return: was the push successful?
        :rtype: bool
        """
        response = requests.post(self.server_url + "ajax/write.php",
                                 data={'data': data},
                                 headers=self.headers,
                                 verify=os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                     self.certificate_filename))
        if response.status_code == requests.codes.ok:
            return True
        else:
            return False

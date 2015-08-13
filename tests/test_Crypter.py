#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from Crypter import Crypter
from base64 import b64encode, b64decode


class TestCrypter(unittest.TestCase):
    def test_encrypt(self):
        message_string = "Important information with quite some length. " + \
                        "This message is as long as this because otherwise only one cipher block would " + \
                        "be encrypted. This long message insures that more than one block is needed."
        password = "secret"
        message = message_string.encode('utf-8')
        crypter = Crypter(password)
        ciphertext = crypter.encrypt(message)
        self.assertEqual(
            b'FRQFCWa38eSIrPnhELojAPrOb8oKzs2yoAbNqVONBEuac3OhUKY12mP+TNyZs1MRUbY9hnqvIG18' +
            b'7MqTAVTzI0fCJhmR4stc/k4YpS+HptmzcTgEfXeli56davPUkmJ59yz2vvF3t/pCUOk0qWNQ2vv9' +
            b'dU2sJhvOdQ7RVKzbw2DJAFtEM2BxJq8Oqa4mB4sBC/GpIP3xtNxANJPyN8xTSL2F4Ktt5hIcX3AV' +
            b'UrnGYSjGeDHGua8iKNFohYtaPj3vvzaSVpGyzAfmlVEdN5/8zQ==',
            b64encode(ciphertext))

    def test_decrypt(self):
        cyphertext = "FRQFCWa38eSIrPnhELojAPrOb8oKzs2yoAbNqVONBEuac3OhUKY12mP+TNyZs1MRUbY9hnqvIG18" + \
                     "7MqTAVTzI0fCJhmR4stc/k4YpS+HptmzcTgEfXeli56davPUkmJ59yz2vvF3t/pCUOk0qWNQ2vv9" + \
                     "dU2sJhvOdQ7RVKzbw2DJAFtEM2BxJq8Oqa4mB4sBC/GpIP3xtNxANJPyN8xTSL2F4Ktt5hIcX3AV" + \
                     "UrnGYSjGeDHGua8iKNFohYtaPj3vvzaSVpGyzAfmlVEdN5/8zQ=="
        self.assertEqual(0, len(b64decode(cyphertext)) % 16)
        password = "secret"
        crypter = Crypter(password)
        self.assertEqual(b'Important information with quite some length. ' +
                         b'This message is as long as this because otherwise only one cipher block would ' +
                         b'be encrypted. This long message insures that more than one block is needed.',
                         crypter.decrypt(b64decode(cyphertext)))

if __name__ == '__main__':
    unittest.main()

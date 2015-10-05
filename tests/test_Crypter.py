#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from crypter import Crypter
from base64 import b64encode, b64decode


class TestCrypter(unittest.TestCase):
    def test_encrypt(self):
        message_string = "Important information with quite some length. " + \
                         "This message is as long as this because otherwise only one cipher block would " + \
                         "be encrypted. This long message insures that more than one block is needed."
        password = "secret"
        message = message_string.encode('utf-8')
        crypter = Crypter(Crypter.createIvKey(password.encode('utf-8'), "pepper".encode('utf-8'), iterations=3))
        ciphertext = crypter.encrypt(message)
        self.assertEqual(
            b'xKadEb1E+adRFKBvEoA3IRuyvYgAxCrleo2vanisBOjoQQI688Hq900K/nIE1o5EnlJ+bOtb6a9u7D3QHtjDk4VP7lZ8exhQD5U' +
            b't7GaZNer1pI66dqae2pL5XR3ulFrpc1mR+8QYPE3Tyu4fbNmEdM5oS6qO1KKQ+6aeEi9arVw8LKIsV2YzsU6lcuCUgoWWJarErf' +
            b'MZ50stwtSBM7uvMRFB9AQ3761A/B8HXJoGJ10kr+5ghh2v1vldp3s9SVcaKyl3GLznaLB3b6dfj55wPA==',
            b64encode(ciphertext))

    def test_decrypt(self):
        ciphertext = b'xKadEb1E+adRFKBvEoA3IRuyvYgAxCrleo2vanisBOjoQQI688Hq900K/nIE1o5EnlJ+bOtb6a9u7D3QHtjDk4VP7l' + \
                     b'Z8exhQD5Ut7GaZNer1pI66dqae2pL5XR3ulFrpc1mR+8QYPE3Tyu4fbNmEdM5oS6qO1KKQ+6aeEi9arVw8LKIsV2Yz' + \
                     b'sU6lcuCUgoWWJarErfMZ50stwtSBM7uvMRFB9AQ3761A/B8HXJoGJ10kr+5ghh2v1vldp3s9SVcaKyl3GLznaLB3b6' + \
                     b'dfj55wPA=='
        self.assertEqual(0, len(b64decode(ciphertext)) % 16)
        password = "secret"
        crypter = Crypter(Crypter.createIvKey(password.encode('utf-8'), "pepper".encode('utf-8'), iterations=3))
        self.assertEqual(b'Important information with quite some length. ' +
                         b'This message is as long as this because otherwise only one cipher block would ' +
                         b'be encrypted. This long message insures that more than one block is needed.',
                         crypter.decrypt(b64decode(ciphertext)))

if __name__ == '__main__':
    unittest.main()

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
        crypter = Crypter("pepper".encode('utf-8'), password)
        ciphertext = crypter.encrypt(message)
        self.assertEqual(
            b'1lsDkebMaZZeO+/DnvVAUYPmXrQOdCAFQ79C3sElpwamOLtX444tRMiecg4/a9394w51dbmKo89CYKpw19nOaKkbF8Dy' +
            b'll9MQJSRUXZEoc3aoaBvgGBCy4rVM62hEQLfpOUdBcrJTPAU3l8zM8V+AN560z7Rj9gXoGkXsotIpEjNg0+hwdmcVRAw' +
            b'JAiDnAbH7K1Q0olPdkM187tbF5A9OEzCU5M36qzUyr/68a1oGL65JCaMAGoHTpQa2i4DlTEkVF1xPkB40ZF167jo360lEQ==',
            b64encode(ciphertext))

    def test_decrypt(self):
        cyphertext = b'1lsDkebMaZZeO+/DnvVAUYPmXrQOdCAFQ79C3sElpwamOLtX444tRMiecg4/a9394w51dbmKo89CYKpw19nOaKkbF8Dy' + \
            b'll9MQJSRUXZEoc3aoaBvgGBCy4rVM62hEQLfpOUdBcrJTPAU3l8zM8V+AN560z7Rj9gXoGkXsotIpEjNg0+hwdmcVRAw' + \
            b'JAiDnAbH7K1Q0olPdkM187tbF5A9OEzCU5M36qzUyr/68a1oGL65JCaMAGoHTpQa2i4DlTEkVF1xPkB40ZF167jo360lEQ=='
        self.assertEqual(0, len(b64decode(cyphertext)) % 16)
        password = "secret"
        crypter = Crypter("pepper".encode('utf-8'), password)
        self.assertEqual(b'Important information with quite some length. ' +
                         b'This message is as long as this because otherwise only one cipher block would ' +
                         b'be encrypted. This long message insures that more than one block is needed.',
                         crypter.decrypt(b64decode(cyphertext)))

if __name__ == '__main__':
    unittest.main()

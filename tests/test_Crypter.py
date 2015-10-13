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
            b'EFEgY5bexGnwjGSUQKK35TPD7fAjG66REq5m9N1eyFHrZQwzv+aLc7bVmJ9FzCyxbCnbyUnzDKiY505br' +
            b'oEb+KO41XKW668xJzh/JvOK0Cu/+bc4/zSFHZM6JsTYEVDIXgR39ZlypeB34jDVI2544w1ey+DmTWbe8n' +
            b'UbagjnmRkok6kOAq8Avsf9BVJMw3BnSn/4cCC+gOxOJY5fp4DecNDQnp0HyyUz2VMMh/JUYILS5+67fXq' +
            b'29CbIQ1DOTqDfqRPA62nkRVPY83cKIe/UXw==',
            b64encode(ciphertext))

    def test_decrypt(self):
        ciphertext = b'EFEgY5bexGnwjGSUQKK35TPD7fAjG66REq5m9N1eyFHrZQwzv+aLc7bVmJ9FzCyxbCnbyUnzDKiY505br' + \
                     b'oEb+KO41XKW668xJzh/JvOK0Cu/+bc4/zSFHZM6JsTYEVDIXgR39ZlypeB34jDVI2544w1ey+DmTWbe8n' + \
                     b'UbagjnmRkok6kOAq8Avsf9BVJMw3BnSn/4cCC+gOxOJY5fp4DecNDQnp0HyyUz2VMMh/JUYILS5+67fXq' + \
                     b'29CbIQ1DOTqDfqRPA62nkRVPY83cKIe/UXw=='
        self.assertEqual(0, len(b64decode(ciphertext)) % 16)
        password = "secret"
        crypter = Crypter(Crypter.createIvKey(password.encode('utf-8'), "pepper".encode('utf-8'), iterations=3))
        self.assertEqual(b'Important information with quite some length. ' +
                         b'This message is as long as this because otherwise only one cipher block would ' +
                         b'be encrypted. This long message insures that more than one block is needed.',
                         crypter.decrypt(b64decode(ciphertext)))

if __name__ == '__main__':
    unittest.main()

#!/usr/bin/python3
# -*- coding: utf-8 -*-

from Crypto.Cipher import AES
from hashlib import pbkdf2_hmac


class Crypter(object):
    def __init__(self, password):
        self.iv = b'\xb5\x4f\xcf\xb0\x88\x09\x55\xe5\xbf\x79\xaf\x37\x71\x1c\x28\xb6'
        salt = "pepper".encode('utf-8')
        self.key = pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 4096)[:32]

    @staticmethod
    def add_pkcs7_padding(data):
        length = 16 - (len(data) % 16)
        data += bytes([length])*length
        return data

    def encrypt(self, data):
        aes_object = AES.new(self.key, AES.MODE_CBC, self.iv)
        return aes_object.encrypt(self.add_pkcs7_padding(data))

    @staticmethod
    def remove_pkcs7_padding(data):
        return data[:-data[-1]]

    def decrypt(self, encrypted_data):
        aes_object = AES.new(self.key, AES.MODE_CBC, self.iv)
        return self.remove_pkcs7_padding(aes_object.decrypt(encrypted_data))

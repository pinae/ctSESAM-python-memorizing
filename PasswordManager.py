#!/usr/bin/python3
# -*- coding: utf-8 -*-

from hashlib import pbkdf2_hmac


class CtSesam(object):
    def __init__(self):
        self.password_characters = []
        self.set_password_character_set()
        self.salt = "pepper".encode('utf-8')

    def set_password_character_set(
            self,
            password_characters='abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.'):
        self.password_characters = password_characters

    def set_salt(self, salt):
        self.salt = salt

    def convert_bytes_to_password(self, digest, length):
        number = int.from_bytes(digest, byteorder='big')
        password = ''
        while number > 0 and len(password) < length:
            password = password + self.password_characters[number % len(self.password_characters)]
            number //= len(self.password_characters)
        return password

    def generate(self, master_password, domain, username='', length=10, iterations=4096):
        if len(self.password_characters) > 0:
            hash_string = domain + username + master_password
            hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), self.salt, iterations)
            return self.convert_bytes_to_password(hashed_bytes, length)
        else:
            print('Für das Passwort stehen keine Zeichen zur Verfügung. Sie sollten die Einstellungen ändern.')
            return ''


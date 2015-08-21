#!/usr/bin/python3
# -*- coding: utf-8 -*-

from hashlib import pbkdf2_hmac


class CtSesam(object):
    """
    Calculates passwords from masterpasswords and domain names. You may set the character set and the salt to
    something of your liking. If not set default values will be used.
    """
    def __init__(self):
        self.password_characters = []
        self.set_password_character_set()
        self.salt = "pepper".encode('utf-8')

    def set_password_character_set(
            self,
            password_characters='abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.'):
        """
        The default character set is
        'abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.'. Please pass a string
        or a list of strings with single characters.
        :param password_characters:
        :return:
        """
        self.password_characters = password_characters

    def set_salt(self, salt):
        """
        The salt should be some random bytes.
        :param salt:
        :return:
        """
        self.salt = salt

    def convert_bytes_to_password(self, digest, length):
        """
        Creates passwords of length length from pseudo-random bytes in digest. You can use this to create random
        passwords by passing random bytes.
        :param digest:
        :param length:
        :return:
        """
        number = int.from_bytes(digest, byteorder='big')
        password = ''
        while number > 0 and len(password) < length:
            password = password + self.password_characters[number % len(self.password_characters)]
            number //= len(self.password_characters)
        return password

    def generate(self, master_password, domain, username='', length=10, iterations=4096):
        """
        This method does all the work. It calculates a password with PBKDF2 and convert_bytes_to_password.
        4096 iterations will give you a password in ~0.04s. If you have a fast computer you can increase this
        to make it harder to hack your masterpassword.
        :param master_password:
        :param domain:
        :param username:
        :param length:
        :param iterations:
        :return:
        """
        if len(self.password_characters) > 0:
            hash_string = domain + username + master_password
            hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), self.salt, iterations)
            return self.convert_bytes_to_password(hashed_bytes, length)
        else:
            print('Für das Passwort stehen keine Zeichen zur Verfügung. Sie sollten die Einstellungen ändern.')
            return ''


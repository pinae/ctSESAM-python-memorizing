#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Password manager. It's name is CtSesam because it produces passwords which are compatible to those created by other
c't SESAM implementations.
"""

from hashlib import pbkdf2_hmac


class CtSesam:
    """
    Calculates passwords from masterpasswords and domain names. You may set the salt and iteration count to
    something of your liking. If not set default values will be used.

    :param domain: the domain str
    :type domain: str
    :param username: the username str
    :type username: str
    :param kgk: the kgk
    :type kgk: bytes
    :param salt: the salt
    :type salt: bytes
    :param iterations: iteration count (should be 1 or higher, default is 4096)
    :type iterations: int
    """
    def __init__(self, domain, username, kgk, salt="pepper".encode('utf-8'), iterations=4096):
        start_value = b''
        for c in domain.encode('utf-8'):
            start_value += bytes([c])
        for c in username.encode('utf-8'):
            start_value += bytes([c])
        for c in kgk:
            start_value += bytes([c])
        if iterations <= 0:
            print("Iteration count was below 1. Hashing 4096 times instead.")
            iterations = 4096
        self.hash_value = pbkdf2_hmac('sha512', start_value, salt, iterations)

    def generate(self, setting):
        """
        Generates a password string.

        :param setting: a setting object
        :type setting: PasswordSetting
        :return: password
        :rtype: str
        """
        number = int.from_bytes(self.hash_value, byteorder='big')
        password = ""
        character_set = setting.get_character_set()
        digits_set = setting.get_digits_character_set()
        lower_set = setting.get_lower_character_set()
        upper_set = setting.get_upper_character_set()
        extra_set = setting.get_extra_character_set()
        template = setting.get_template()
        for t in template:
            if number > 0:
                if t == 'a':
                    current_set = lower_set
                elif t == 'A':
                    current_set = upper_set
                elif t == 'n':
                    current_set = digits_set
                elif t == 'o':
                    current_set = extra_set
                else:
                    current_set = character_set
                if len(current_set) > 0:
                    password = password + current_set[number % len(current_set)]
                    number //= len(current_set)
        return password

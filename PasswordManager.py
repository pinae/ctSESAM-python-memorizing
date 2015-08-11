#!/usr/bin/python3
# -*- coding: utf-8 -*-

from hashlib import pbkdf2_hmac


class CtSesam(object):
    def __init__(self):
        self.password_characters = []
        self.set_password_characters()
        self.salt = "pepper".encode('utf-8')

    def set_password_characters(self, use_letters=True, use_digits=True, use_special_characters=True):
        if not use_letters and not use_digits and not use_special_characters:
            use_letters = True
            use_digits = True
            use_special_characters = True
        lower_case_letters = list('abcdefghijklmnopqrstuvwxyz')
        upper_case_letters = list('ABCDEFGHJKLMNPQRTUVWXYZ')
        digits = list('0123456789')
        special_characters = list('#!"§$%&/()[]{}=-_+*<>;:.')
        self.password_characters = []
        if use_letters:
            self.password_characters += lower_case_letters + upper_case_letters
        if use_digits:
            self.password_characters += digits
        if use_special_characters:
            self.password_characters += special_characters

    def convert_bytes_to_password(self, digest, length):
        number = int.from_bytes(digest, byteorder='big')
        password = ''
        while number > 0 and len(password) < length:
            password = password + self.password_characters[number % len(self.password_characters)]
            number //= len(self.password_characters)
        return password

    def generate(self, master_password, domain, username='', length=10, iterations=4096):
        hash_string = domain + username + master_password
        hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), self.salt, iterations)
        return self.convert_bytes_to_password(hashed_bytes, length)


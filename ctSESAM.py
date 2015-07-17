#!/usr/bin/python3
# -*- coding: utf-8 -*-

from hashlib import pbkdf2_hmac

small_letters = list('abcdefghijklmnopqrstuvwxyz')
big_letters = list('ABCDEFGHJKLMNPQRTUVWXYZ')
numbers = list('0123456789')
special_characters = list('#!"§$%&/()[]{}=-_+*<>;:.')
password_characters = small_letters + big_letters + numbers + special_characters
salt = "pepper"


def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder='big')
    password = ''
    while number > 0 and len(password) < length:
        password = password + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    return password

master_password = input('Masterpasswort: ')
domain = input('Domain: ')
while len(domain) < 1:
    print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
    domain = input('Domain: ')
hash_string = domain + master_password
hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), salt.encode('utf-8'), 4096)
print('Passwort: ' + convert_bytes_to_password(hashed_bytes, 10))

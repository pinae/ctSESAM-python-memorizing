#!/usr/bin/python3

from hashlib import sha256

big_letters = list('ABCDEFGHJKLMNPQRTUVWXYZ')
small_letters = list('abcdefghijklmnopqrstuvwxyz')
numbers = list('0123456789')
special_characters = list('#!"§$%&/()[]{}=-_+*<>;:.')
password_characters = special_characters + big_letters + small_letters + numbers
salt = "c't ist toll!"


def convert_bytes_to_password(bytes):
    number = int.from_bytes(bytes, byteorder='big')
    string = ''
    while number >= len(password_characters):
        string = string + password_characters[number % len(password_characters)]
        number = number // len(password_characters) - 1
    string = string + password_characters[number]
    return string

domain = input('Domain: ')
master_password = input('Masterpasswort: ')
hasher = sha256()
hash_string = domain + master_password + salt
hasher.update(hash_string.encode('utf-8'))
print('Passwort: ' + convert_bytes_to_password(hasher.digest())[-10:])

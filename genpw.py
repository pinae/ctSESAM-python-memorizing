#!/usr/bin/python3

from hashlib import pbkdf2_hmac

small_letters = list('abcdefghijklmnopqrstuvwxyz')
big_letters = list('ABCDEFGHJKLMNPQRTUVWXYZ')
numbers = list('0123456789')
special_characters = list('#!"§$%&/()[]{}=-_+*<>;:.')
password_characters = small_letters + big_letters + numbers + special_characters
salt = "pepper"


def convert_bytes_to_password(hashed_bytes, length):
    number = int.from_bytes(hashed_bytes, byteorder='big')
    string = ''
    while number >= len(password_characters) and len(string) < length:
        string = string + password_characters[number % len(password_characters)]
        number = number // len(password_characters)
    if number < len(password_characters) and len(string) < length:
        string = string + password_characters[number]
    return string

domain = input('Domain: ')
while len(domain) < 1:
    print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
    domain = input('Domain: ')
master_password = input('Masterpasswort: ')
hash_string = domain + master_password
hashed_bytes = pbkdf2_hmac('sha512', hash_string.encode('utf-8'), salt.encode('utf-8'), 4096)
print('Passwort: ' + convert_bytes_to_password(hashed_bytes, 10))

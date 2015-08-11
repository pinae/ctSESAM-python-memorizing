#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
from hashlib import pbkdf2_hmac
import random
import string
import configparser


DEFAULT_CONFIG='~/ctSESAM.ini'
SPECIAL_CHARACTERS = '#!"§$%&/()[]{}=-_+*<>;:.'
PASSWORD_CHARACTERS = string.ascii_letters + string.digits + SPECIAL_CHARACTERS


class SesamConfig(object):
    def __init__(self, filepath=None, verbose=True):
        self.filepath = os.path.expanduser(filepath or DEFAULT_CONFIG)
        self.verbose = verbose

    def create_and_read(self):
        """
        Load config from a existing .ini file.
        Create a default .ini, if not exist.
        """
        if not os.path.isfile(self.filepath):
            self.write_defaults()
        self.load_from_config()

    def write_defaults(self):
        """
        Create .ini file with defaults and a new, random 'salt' value.
        """
        config = configparser.ConfigParser()
        config['pbkdf2'] = {"hash_name": "sha512", "iterations": 4096}
        config['user_settings'] = {
            "salt": ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10)),
            "default_length": 10,
        }
        with open(self.filepath, "w") as f:
            f.write("# config file for c't SESAM\n")
            f.write("# Please make a backup!\n")
            config.write(f)
        if self.verbose:
            print("\nConfig file created here:")
            print(self.filepath)
            print("Please make a backup!\n")

    def load_from_config(self):
        """
        Load config from a .ini file.
        The file and all config entries must exist.
        """
        config = configparser.ConfigParser()
        read_ok = config.read(self.filepath, encoding="utf-8")
        if self.filepath not in read_ok:
            raise RuntimeError("Error reading config file: %s" % self.filepath)

        try:
            self.hash_name = config['pbkdf2']['hash_name']
            self.iterations = config.getint('pbkdf2', 'iterations')
            self.salt = config['user_settings']['salt']
            self.default_length = config.getint('user_settings', 'default_length')
        except KeyError as err:
            raise RuntimeError("Can't parse config file '%s' KeyError: %s" % (self.filepath, err))


def convert_bytes_to_password(hashed_bytes, length):
    numbers = int.from_bytes(hashed_bytes, byteorder='big')
    password = ''
    while numbers > 0 and len(password) < length:
        password = password + PASSWORD_CHARACTERS[numbers % len(PASSWORD_CHARACTERS)]
        numbers = numbers // len(PASSWORD_CHARACTERS)
    return password


def generate_password(domain, master_password, cfg):
    hash_string = bytes(domain + master_password, "utf-8")
    salt = bytes(cfg.salt, "utf-8")
    hashed_bytes = pbkdf2_hmac(cfg.hash_name, hash_string, salt, cfg.iterations)
    return convert_bytes_to_password(hashed_bytes, cfg.default_length)


def cli(cfg):
    master_password = input('Masterpasswort: ')
    domain = ""
    while not domain:
        print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
        domain = input('Domain: ')

    password = generate_password(domain, master_password, cfg)
    print('Passwort: %s' % password)


if __name__ == "__main__":
    cfg = SesamConfig()
    cfg.create_and_read()
    cli(cfg)

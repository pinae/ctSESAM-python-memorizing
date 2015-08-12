#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import string
import random
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
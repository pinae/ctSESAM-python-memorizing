#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
The preference manager handles the access to the settings file.
"""
import os

PASSWORD_SETTINGS_FILE = os.path.expanduser('~/.ctSESAM.pws')


class PreferenceManager(object):
    """


    :param settings_file: Filename of the settings file. Defaults to PASSWORD_SETTINGS_FILE as defined in the source
    :type settings_file: str
    """
    def __init__(self, settings_file=PASSWORD_SETTINGS_FILE):
        self.data = b''
        self.settings_file = settings_file
        self.read_file()

    def read_file(self):
        """
        Read the settings file.
        """
        if os.path.isfile(self.settings_file):
            with open(self.settings_file, 'rb') as f:
                self.data = f.read()

    def get_salt(self):
        """
        Reads the salt.

        :return: the salt
        :rtype: bytes
        """
        return self.data[:32]

    def store_salt(self, salt):
        """
        Writes the salt into the first 32 bytes of the file.

        :param salt: 32 bytes salt
        :type salt: bytes
        """
        if type(salt) != bytes:
            raise TypeError("The salt must be bytes.")
        if len(salt) != 32:
            raise ValueError("The salt has to be 32 bytes.")
        if os.path.isfile(self.settings_file):
            with open(self.settings_file, 'rb+') as file:
                file.seek(0)
                file.write(salt)
        else:
            with open(self.settings_file, 'wb') as file:
                file.write(salt)
        self.data = salt + self.data[32:]
        self.set_hidden()

    def get_kgk_block(self):
        """
        Reads the kgk_block.

        :return: 112 bytes of kgk data
        :rtype: bytes
        """
        return self.data[32:144]

    def store_kgk_block(self, kgk_block):
        """
        Writes the kgk_block into bytes 32 to 143.

        :param kgk_block: encrypted kgk data
        :type kgk_block: bytes
        """
        if type(kgk_block) != bytes:
            raise TypeError("The kgk_block must be bytes.")
        if len(kgk_block) != 112:
            raise ValueError("The kgk_block has to be 112 bytes.")
        if os.path.isfile(self.settings_file):
            with open(self.settings_file, 'rb+') as file:
                file.seek(32)
                file.write(kgk_block)
        else:
            with open(self.settings_file, 'wb') as file:
                file.write(b'\x00'*32)
                file.write(kgk_block)
        self.data = self.data[:32] + kgk_block + self.data[144:]
        self.set_hidden()

    def get_settings_data(self):
        """
        Reads the settings data.

        :return: encrypted settings
        :rtype: bytes
        """
        return self.data[144:]

    def store_settings_data(self, settings_data):
        """
        Writes the settings data after byte 144.

        :param settings_data: encrypted settings data
        :type settings_data: bytes
        """
        if type(settings_data) != bytes:
            raise TypeError("The kgk_block must be bytes.")
        if os.path.isfile(self.settings_file):
            with open(self.settings_file, 'rb+') as file:
                file.seek(144)
                file.write(settings_data)
                file.truncate()
        else:
            with open(self.settings_file, 'wb') as file:
                file.write(b'\x00'*144)
                file.write(settings_data)
        self.data = self.data[:144] + settings_data
        self.set_hidden()

    # noinspection PyUnresolvedReferences
    def set_hidden(self):
        """
        Hides the settings file if possible.
        """
        try:
            import win32con
            import win32api
            win32api.SetFileAttributes(self.settings_file, win32con.FILE_ATTRIBUTE_HIDDEN)
        except ImportError:
            pass

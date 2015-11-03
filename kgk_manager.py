#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
The KGK manager stores the kgk and manages storage and encryption of kgk blocks.
"""

from preference_manager import PreferenceManager
from crypter import Crypter
from binascii import hexlify
import os


class KgkManager:
    """
    New KgkManagers are uninitialized and need either a new kgk or get one by decrypting an existing one.
    """
    def __init__(self):
        self.preference_manager = None
        self.kgk = b''
        self.iv2 = None
        self.salt2 = None
        self.kgk_crypter = None
        self.salt = b''

    def __str__(self):
        attr = ["KGK: " + str(hexlify(self.kgk), encoding='utf-8'),
                "salt: " + str(hexlify(self.salt), encoding='utf-8')]
        if self.iv2:
            attr.append("iv2: " + str(hexlify(self.iv2), encoding='utf-8'))
        if self.salt2:
            attr.append("salt2: " + str(hexlify(self.salt2), encoding='utf-8'))
        return "<" + ", ".join(attr) + ">"

    def set_preference_manager(self, preference_manager):
        """
        Pass a preference manager to load and store settings locally

        :param preference_manager:
        :type preference_manager: PreferenceManager
        """
        if type(preference_manager) != PreferenceManager:
            raise TypeError
        self.preference_manager = preference_manager

    def get_kgk_crypter_salt(self):
        """
        Loads the public salt. If there is none it is created and stored.

        :return:
        """
        self.salt = self.preference_manager.get_salt()
        if len(self.salt) != 32:
            self.salt = Crypter.createSalt()
            self.store_salt(self.salt)
        return self.salt

    def store_salt(self, salt):
        """
        Stores the salt using the preference manager.

        :param salt: the salt
        :type salt: bytes
        """
        if type(salt) == bytes:
            self.salt = salt
            if self.preference_manager:
                self.preference_manager.store_salt(salt)
        else:
            raise TypeError("There is no salt to be saved")

    def get_kgk_crypter(self, password, salt):
        """
        Creates a kgk crypter for the given credentials. This is a very expensive operation.

        :param password:
        :type password: bytes
        :param salt:
        :type salt: bytes
        :return: a kgk crypter
        :rtype: Crypter
        """
        self.kgk_crypter = Crypter(Crypter.createIvKey(password=password, salt=salt))
        self.store_salt(salt=salt)
        return self.kgk_crypter

    def create_new_kgk(self):
        """
        Creates a new kgk. This overwrites the previous one.

        :return: the new kgk
        :rtype: bytes
        """
        self.kgk = os.urandom(64)
        self.iv2 = Crypter.createIv()
        self.salt2 = Crypter.createSalt()
        return self.kgk

    def decrypt_kgk(self, encrypted_kgk, kgk_crypter=None, password=b'', salt=b''):
        """
        Decrypts kgk blobs. If a crypter is passed it is used. If none is passed a new crypter is created with
        the salt and password. This takes relatively long. If the encrypted_kgk has a wrong length a new kgk is
        created.

        :param encrypted_kgk:
        :type encrypted_kgk: bytes
        :param kgk_crypter:
        :type kgk_crypter: Crypter
        :param password:
        :type password: bytes
        :param salt:
        :type salt: bytes
        """
        if kgk_crypter:
            self.kgk_crypter = kgk_crypter
        else:
            if len(salt) < 32:
                salt = Crypter.createSalt()
            self.get_kgk_crypter(password, salt)
        if len(encrypted_kgk) == 112:
            kgk_block = self.kgk_crypter.decrypt_unpadded(encrypted_kgk)
            self.salt2 = kgk_block[:32]
            self.iv2 = kgk_block[32:48]
            self.kgk = kgk_block[48:112]
        else:
            self.create_new_kgk()

    def get_kgk(self):
        """
        Returns the kgk.

        :return: the kgk
        :rtype: bytes
        """
        return self.kgk

    def has_kgk(self):
        """
        Returns true if there is a kgk and a crypter.

        :return: kgk state
        :rtype: bool
        """
        return not not self.kgk and len(self.kgk) == 64 and self.kgk_crypter

    def get_salt2(self):
        """
        Returns the salt2

        :return: salt2
        :rtype: bytes
        """
        return self.salt2

    def get_iv2(self):
        """
        Returns the iv2

        :return: iv2
        :rtype: bytes
        """
        return self.iv2

    def fresh_salt2(self):
        """
        Creates a fresh salt for the settings encryption (salt2).
        """
        self.salt2 = Crypter.createSalt()

    def fresh_iv2(self):
        """
        Creates a fresh iv for the settings encryption (iv2).
        """
        self.iv2 = Crypter.createIv()

    def get_encrypted_kgk(self):
        """
        Returns an encrypted kgk block.

        :return: kgk block
        :rtype: bytes
        """
        return self.kgk_crypter.encrypt_unpadded(self.salt2 + self.iv2 + self.kgk)

    def get_fresh_encrypted_kgk(self):
        """
        Returns a new encrypted kgk block with fresh salt2 and iv2. This does not create a new kgk.

        :return: kgk block
        :rtype: bytes
        """
        self.fresh_iv2()
        self.fresh_salt2()
        return self.get_encrypted_kgk()

    def create_and_save_new_kgk_block(self, kgk_crypter=None):
        """
        Creates a fresh kgk block and saves it.

        :param kgk_crypter:
        :type kgk_crypter: Crypter
        :return: kgk block
        :rtype: bytes
        """
        self.salt = Crypter.createSalt()
        self.store_salt(self.salt)
        if kgk_crypter:
            self.kgk_crypter = kgk_crypter
        kgk_block = self.get_fresh_encrypted_kgk()
        self.preference_manager.store_kgk_block(kgk_block)
        return kgk_block

    def update_from_blob(self, password, blob):
        """
        Updates the kgk from a remote data blob.

        :param password: the masterpassword
        :type password: bytes
        :param blob: the encrypted data
        :type blob: bytes
        """
        if blob[0] != 1 or len(blob) < 145:
            raise ValueError("Version error: Wrong data format. Could not import anything.")
        salt = blob[1:33]
        kgk_block = blob[33:145]
        self.decrypt_kgk(encrypted_kgk=kgk_block, password=password, salt=salt)

    def store_local_kgk_block(self):
        """
        Stores the local kgk block.
        """
        if self.preference_manager:
            self.preference_manager.store_kgk_block(self.get_encrypted_kgk())
        if len(self.salt) == 32:
            self.store_salt(self.salt)
        else:
            raise ValueError("The salt has to be 32 bytes.")

    def reset(self):
        """
        Resets the kgk manager.
        """
        self.salt = b''
        self.iv2 = None
        self.salt2 = None
        self.kgk = b''
        self.kgk_crypter = None

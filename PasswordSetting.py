#!/usr/bin/python3
# -*- coding: utf-8 -*-

from datetime import datetime
import string
import json
from base64 import b64encode, b64decode

DEFAULT_SALT = "pepper".encode('utf-8')
DEFAULT_CHARACTER_SET_LOWER_CASE = "abcdefghijklmnopqrstuvwxyz"
DEFAULT_CHARACTER_SET_UPPER_CASE = "ABCDEFGHJKLMNPQRTUVWXYZ"
DEFAULT_CHARACTER_SET_DIGITS = string.digits
DEFAULT_CHARACTER_SET_EXTRA = '#!"§$%&/()[]{}=-_+*<>;:.'


class PasswordSetting(object):
    def __init__(self, domain):
        self.domain = domain
        self.username = None
        self.legacy_password = None
        self.notes = None
        self.iterations = 4096
        self.salt = DEFAULT_SALT
        self.length = 10
        self.creation_date = datetime.now()
        self.modification_date = self.creation_date
        self.used_characters = self.get_default_character_set()
        self.synced = False

    def get_domain(self):
        return self.domain

    def set_domain(self, domain):
        self.domain = domain
        self.synced = False

    def get_username(self):
        if self.username:
            return self.username
        else:
            return ""

    def set_username(self, username):
        self.username = username
        self.synced = False

    def get_legacy_password(self):
        if self.legacy_password:
            return self.legacy_password
        else:
            return ""

    def set_legacy_password(self, legacy_password):
        self.legacy_password = legacy_password
        self.synced = False

    def use_letters(self):
        return self.used_characters[:len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE)] == \
            DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE

    def set_use_letters(self, use_letters):
        old_character_set = self.used_characters
        pos = 0
        while pos < len(self.used_characters):
            if self.used_characters[pos] in DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE:
                self.used_characters = self.used_characters[:pos] + self.used_characters[pos + 1:]
            else:
                pos += 1
        if use_letters:
            self.used_characters = DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
                self.used_characters
        if old_character_set != self.used_characters:
            self.synced = False

    def use_lower_case(self):
        return self.used_characters[:len(DEFAULT_CHARACTER_SET_LOWER_CASE)] == DEFAULT_CHARACTER_SET_LOWER_CASE

    def set_use_lower_case(self, use_lower_case):
        old_character_set = self.used_characters
        pos = 0
        while pos < len(self.used_characters):
            if self.used_characters[pos] in DEFAULT_CHARACTER_SET_LOWER_CASE:
                self.used_characters = self.used_characters[:pos] + self.used_characters[pos + 1:]
            else:
                pos += 1
        if use_lower_case:
            self.used_characters = DEFAULT_CHARACTER_SET_LOWER_CASE + self.used_characters
        if old_character_set != self.used_characters:
            self.synced = False

    def use_upper_case(self):
        return self.used_characters[
            len(DEFAULT_CHARACTER_SET_LOWER_CASE):len(
                DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE)] \
            == DEFAULT_CHARACTER_SET_UPPER_CASE

    def set_use_upper_case(self, use_upper_case):
        old_character_set = self.used_characters
        pos = 0
        while pos < len(self.used_characters):
            if self.used_characters[pos] in DEFAULT_CHARACTER_SET_UPPER_CASE:
                self.used_characters = self.used_characters[:pos] + self.used_characters[pos + 1:]
            else:
                pos += 1
        if use_upper_case:
            self.used_characters = self.used_characters[:len(DEFAULT_CHARACTER_SET_LOWER_CASE)] + \
                DEFAULT_CHARACTER_SET_LOWER_CASE + self.used_characters[len(DEFAULT_CHARACTER_SET_LOWER_CASE):]
        if old_character_set != self.used_characters:
            self.synced = False

    def use_digits(self):
        return self.used_characters[
            len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE):len(
                DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + DEFAULT_CHARACTER_SET_DIGITS)] \
            == DEFAULT_CHARACTER_SET_DIGITS

    def set_use_digits(self, use_digits):
        old_character_set = self.used_characters
        pos = 0
        while pos < len(self.used_characters):
            if self.used_characters[pos] in DEFAULT_CHARACTER_SET_DIGITS:
                self.used_characters = self.used_characters[:pos] + self.used_characters[pos + 1:]
            else:
                pos += 1
        if use_digits:
            self.used_characters = self.used_characters[
                :len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE)] + \
                DEFAULT_CHARACTER_SET_DIGITS + self.used_characters[
                    len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE):]
        if old_character_set != self.used_characters:
            self.synced = False

    def use_extra(self):
        return self.used_characters[
            len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + DEFAULT_CHARACTER_SET_DIGITS):] \
            == DEFAULT_CHARACTER_SET_EXTRA

    def set_use_extra(self, use_extra):
        old_character_set = self.used_characters
        pos = 0
        while pos < len(self.used_characters):
            if self.used_characters[pos] in DEFAULT_CHARACTER_SET_EXTRA:
                self.used_characters = self.used_characters[:pos] + self.used_characters[pos + 1:]
            else:
                pos += 1
        if use_extra:
            self.used_characters += DEFAULT_CHARACTER_SET_EXTRA
        if old_character_set != self.used_characters:
            self.synced = False

    def use_custom_character_set(self):
        return not self.used_characters == DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
            DEFAULT_CHARACTER_SET_DIGITS + DEFAULT_CHARACTER_SET_EXTRA

    @staticmethod
    def get_default_character_set():
        return DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
            DEFAULT_CHARACTER_SET_DIGITS + DEFAULT_CHARACTER_SET_EXTRA

    def get_character_set(self):
        return self.used_characters

    def set_custom_character_set(self, character_set):
        if self.used_characters != character_set:
            self.synced = False
        self.used_characters = character_set

    def get_salt(self):
        return self.salt

    @staticmethod
    def get_default_salt():
        return DEFAULT_SALT

    def set_salt(self, salt):
        if type(salt) == bytes:
            if self.salt != salt:
                self.synced = False
            self.salt = salt
        elif type(salt) == str:
            if self.salt != salt.encode('utf-8'):
                self.synced = False
            self.salt = salt.encode('utf-8')
        else:
            raise TypeError("The salt should be bytes.")

    def get_length(self):
        return self.length

    def set_length(self, length):
        if self.length != length:
            self.synced = False
        self.length = length

    def get_iterations(self):
        return self.iterations

    def set_iterations(self, iterations):
        if self.iterations != iterations:
            self.synced = False
        self.iterations = iterations

    def get_c_date(self):
        return self.creation_date

    def get_creation_date(self):
        return self.creation_date.strftime("%Y-%m-%dT%H:%M:%S")

    def set_creation_date(self, creation_date):
        if self.creation_date != creation_date:
            self.synced = False
        try:
            self.creation_date = datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            print("This date has a wrong format: " + creation_date)
            self.creation_date = datetime.now()
        if self.modification_date < self.creation_date:
            self.modification_date = self.creation_date

    def get_m_date(self):
        return self.modification_date

    def get_modification_date(self):
        return self.modification_date.strftime("%Y-%m-%dT%H:%M:%S")

    def set_modification_date(self, modification_date=None):
        if modification_date and self.modification_date != modification_date:
            self.synced = False
        if type(modification_date) == str:
            try:
                self.modification_date = datetime.strptime(modification_date, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                print("This date has a wrong format: " + modification_date)
                self.modification_date = datetime.now()
        else:
            self.modification_date = datetime.now()
        if self.modification_date < self.creation_date:
            print("The modification date was before the creation Date. " +
                  "Setting the creation date to the earlier date.")
            self.creation_date = self.modification_date

    def get_notes(self):
        if self.notes:
            return self.notes
        else:
            return ""

    def set_notes(self, notes):
        self.notes = notes

    def is_synced(self):
        return self.synced

    def set_synced(self, is_synced=True):
        self.synced = is_synced

    def to_dict(self):
        domain_object = {"domain": self.get_domain()}
        if self.get_username():
            domain_object["username"] = self.get_username()
        if self.get_legacy_password():
            domain_object["legacyPassword"] = self.get_legacy_password()
        if self.notes:
            domain_object["notes"] = self.get_notes()
        domain_object["iterations"] = self.get_iterations()
        if self.salt:
            domain_object["salt"] = str(b64encode(self.get_salt()), encoding='utf-8')
        domain_object["length"] = self.get_length()
        domain_object["cDate"] = self.get_creation_date()
        domain_object["mDate"] = self.get_modification_date()
        domain_object["usedCharacters"] = self.get_character_set()
        return domain_object

    def load_from_dict(self, loaded_setting):
        if "domain" in loaded_setting:
            self.set_domain(loaded_setting["domain"])
        if "username" in loaded_setting:
            self.set_username(loaded_setting["username"])
        if "legacyPassword" in loaded_setting:
            self.set_legacy_password(loaded_setting["legacyPassword"])
        if "notes" in loaded_setting:
            self.set_notes(loaded_setting["notes"])
        if "iterations" in loaded_setting:
            self.set_iterations(loaded_setting["iterations"])
        if "salt" in loaded_setting:
            self.set_salt(b64decode(loaded_setting["salt"]))
        if "length" in loaded_setting:
            self.set_length(loaded_setting["length"])
        if "cDate" in loaded_setting:
            self.set_creation_date(loaded_setting["cDate"])
        if "mDate" in loaded_setting:
            self.set_modification_date(loaded_setting["mDate"])
        if "usedCharacters" in loaded_setting:
            self.set_custom_character_set(loaded_setting["usedCharacters"])

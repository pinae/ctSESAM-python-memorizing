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
        self.salt = DEFAULT_SALT
        self.creation_date = datetime.now()
        self.modification_date = self.creation_date
        self.username = None
        self.legacy_password = None
        self.use_lower = True
        self.use_upper = True
        self.use_digit_characters = True
        self.use_special_characters = True
        self.use_custom = False
        self.avoid_ambiguous = True
        self.custom_character_set = None
        self.length = 10
        self.iterations = 4096
        self.notes = None
        self.synced = False

    def get_domain(self):
        return self.domain

    def set_domain(self, domain):
        self.domain = domain

    def get_username(self):
        if self.username:
            return self.username
        else:
            return ""

    def set_username(self, username):
        self.username = username

    def get_legacy_password(self):
        if self.legacy_password:
            return self.legacy_password
        else:
            return ""

    def set_legacy_password(self, legacy_password):
        self.legacy_password = legacy_password

    def use_letters(self):
        return self.use_lower and self.use_upper

    def set_use_letters(self, use_letters):
        self.use_lower = use_letters
        self.use_upper = use_letters

    def use_lower_case(self):
        return self.use_lower

    def set_use_lower_case(self, use_lower_case):
        self.use_lower = use_lower_case

    def use_upper_case(self):
        return self.use_upper

    def set_use_upper_case(self, use_upper_case):
        self.use_upper = use_upper_case

    def use_digits(self):
        return self.use_digit_characters

    def set_use_digits(self, use_digits):
        self.use_digit_characters = use_digits

    def use_extra(self):
        return self.use_special_characters

    def set_use_extra(self, use_extra):
        self.use_special_characters = use_extra

    def use_custom_character_set(self):
        return self.use_custom

    def avoid_ambiguous_characters(self):
        return self.avoid_ambiguous

    def set_avoid_ambiguous_characters(self, avoid_ambiguous_characters):
        self.avoid_ambiguous = avoid_ambiguous_characters

    def get_default_character_set(self):
        character_set = ""
        if self.use_lower_case():
            character_set += DEFAULT_CHARACTER_SET_LOWER_CASE
        if self.use_upper_case():
            character_set += DEFAULT_CHARACTER_SET_UPPER_CASE
        if self.use_digits():
            character_set += DEFAULT_CHARACTER_SET_DIGITS
        if self.use_extra():
            character_set += DEFAULT_CHARACTER_SET_EXTRA
        return character_set

    def get_custom_character_set(self):
        if self.custom_character_set:
            return self.custom_character_set
        else:
            return ""

    def set_custom_character_set(self, character_set):
        if character_set == self.get_default_character_set():
            self.use_custom = False
            self.custom_character_set = None
        else:
            self.use_custom = True
            self.custom_character_set = character_set

    def get_character_set(self):
        if self.use_custom_character_set():
            return self.get_custom_character_set()
        else:
            return self.get_default_character_set()

    def get_salt(self):
        return self.salt

    @staticmethod
    def get_default_salt():
        return DEFAULT_SALT

    def set_salt(self, salt):
        if type(salt) == bytes:
            self.salt = salt
        elif type(salt) == str:
            self.salt = salt.encode('utf-8')
        else:
            raise TypeError("The salt should be bytes.")

    def get_length(self):
        return self.length

    def set_length(self, length):
        self.length = length

    def get_iterations(self):
        return self.iterations

    def set_iterations(self, iterations):
        self.iterations = iterations

    def get_creation_date(self):
        return self.creation_date.strftime("%Y-%m-%dT%H:%M:%S")

    def set_creation_date(self, creation_date):
        try:
            self.creation_date = datetime.strptime(creation_date, "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            print("This date has a wrong format: " + creation_date)
            self.creation_date = datetime.now()
        if self.modification_date < self.creation_date:
            self.modification_date = self.creation_date

    def get_modification_date(self):
        return self.modification_date.strftime("%Y-%m-%dT%H:%M:%S")

    def set_modification_date(self, modification_date=None):
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
        self.synced = False

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

    def to_json(self):
        domain_object = {
            "domain": self.get_domain(),
            "useLowerCase": self.use_lower_case(),
            "useUpperCase": self.use_upper_case(),
            "useDigits": self.use_digits(),
            "useExtra": self.use_extra(),
            "iterations": self.get_iterations(),
            "length": self.get_length(),
            "cDate": self.get_creation_date(),
            "mDate": self.get_modification_date()
        }
        if self.salt:
            domain_object["salt"] = str(b64encode(self.get_salt()))
        if self.use_custom_character_set():
            domain_object["useCustom"] = True
            domain_object["customCharacterSet"] = self.get_custom_character_set()
        if self.notes:
            domain_object["notes"] = self.get_notes()
        return json.dumps(domain_object)

    def load_from_json(self, loaded_setting):
        domain_object = json.loads(loaded_setting)
        if "domain" in domain_object:
            self.set_domain(domain_object["domain"])
        if "username" in domain_object:
            self.set_username(domain_object["username"])
        if "legacyPassword" in domain_object:
            self.set_legacy_password(domain_object["legacyPassword"])
        if "salt" in domain_object:
            self.set_salt(b64decode(domain_object["salt"]))
        if "cDate" in domain_object:
            self.set_creation_date(domain_object["cDate"])
        if "mDate" in domain_object:
            self.set_modification_date(domain_object["mDate"])
        if "iterations" in domain_object:
            self.set_iterations(domain_object["iterations"])
        if "length" in domain_object:
            self.set_length(domain_object["length"])
        if "useUpperCase" in domain_object:
            self.set_use_upper_case(domain_object["useUpperCase"])
        if "useLowerCase" in domain_object:
            self.set_use_lower_case(domain_object["useLowerCase"])
        if "useDigits" in domain_object:
            self.set_use_digits(domain_object["useDigits"])
        if "useExtra" in domain_object:
            self.set_use_extra(domain_object["useExtra"])
        if "avoidAmbiguous" in domain_object:
            self.set_avoid_ambiguous_characters(domain_object["avoidAmbiguous"])
        if "useCustom" in domain_object and domain_object["useCustom"] and \
           "customCharacterSet" in domain_object and len(domain_object["customCharacterSet"]) > 0:
            self.set_custom_character_set(domain_object["customCharacterSet"])
        if "notes" in domain_object:
            self.set_notes(domain_object["notes"])

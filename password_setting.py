#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Sets of password settings for a domain.
"""

from datetime import datetime
import getpass
import string
import re
import binascii
from base64 import b64encode, b64decode
from random import shuffle
from crypter import Crypter

DEFAULT_CHARACTER_SET_LOWER_CASE = string.ascii_lowercase
DEFAULT_CHARACTER_SET_UPPER_CASE = string.ascii_uppercase
DEFAULT_CHARACTER_SET_DIGITS = string.digits
DEFAULT_CHARACTER_SET_EXTRA = '#!"§$%&/()[]{}=-_+*<>;:.'


class PasswordSetting:
    """
    This saves one set of settings for a certain domain. Use a PasswordSettingsManager to save the settings to a file.
    """
    def __init__(self, domain):
        self.domain = domain
        self.url = None
        self.username = None
        self.legacy_password = None
        self.notes = None
        self.iterations = 4096
        self.salt = Crypter.createSalt()
        self.length = 10
        self.creation_date = datetime.now()
        self.modification_date = self.creation_date
        self.used_characters = self.get_default_character_set()
        self.extra_characters = DEFAULT_CHARACTER_SET_EXTRA
        self.template = None
        self.force_character_classes = False
        self.synced = False

    def __str__(self):
        output = "<" + self.domain + ": ("
        if self.username:
            output += "username: " + str(self.username) + ", "
        if self.legacy_password:
            output += "legacy password: " + str(self.legacy_password) + ", "
        if self.notes:
            output += "notes: " + str(self.notes) + ", "
        output += "iterations: " + str(self.iterations) + ", "
        output += "salt: " + str(binascii.hexlify(self.salt)) + ", "
        if self.force_character_classes and self.template:
            output += "template: " + str(self.template) + ", "
        else:
            output += "length: " + str(self.length) + ", "
        output += "modification date: " + self.get_modification_date() + ", "
        output += "creation date: " + self.get_creation_date() + ", "
        output += "used characters: \"" + self.used_characters + "\", "
        if self.extra_characters:
            output += "extra characters: \"" + self.extra_characters + "\", "
        if self.use_lower_case():
            output += "using lower case characters, "
        if self.use_upper_case():
            output += "using upper case characters, "
        if self.use_digits():
            output += "using digits, "
        if self.use_extra():
            output += "using special characters, "
        if self.synced:
            output += "synced"
        else:
            output += "not synced"
        output += ")>"
        return output

    def get_domain(self):
        """
        Returns the domain name or another string used in the domain field.

        :return: the domain
        :rtype: str
        """
        return self.domain

    def set_domain(self, domain):
        """
        Change the domain string.

        :param domain: the domain
        :type domain: str
        """
        self.domain = domain
        self.synced = False

    def has_username(self):
        """
        Returns True if the username is set.

        :return:
        :rtype: bool
        """
        return self.username and len(str(self.username)) > 0

    def get_username(self):
        """
        Returns the username or an empty string if there was no username.

        :return: the username
        :rtype: str
        """
        if self.username:
            return self.username
        else:
            return ""

    def set_username(self, username):
        """
        Set the username.

        :param username: the username
        :type username: str
        """
        if username != self.username:
            self.synced = False
        self.username = username

    def has_legacy_password(self):
        """
        Returns True if the legacy password is set.

        :return:
        :rtype: bool
        """
        return self.legacy_password and len(str(self.legacy_password)) > 0

    def get_legacy_password(self):
        """
        Returns the legacy password if set or an empty string otherwise.

        :return: the legacy password
        :rtype: str
        """
        if self.legacy_password:
            return self.legacy_password
        else:
            return ""

    def set_legacy_password(self, legacy_password):
        """
        Set a legacy password.

        :param legacy_password: a legacy password
        :type legacy_password: str
        """
        if legacy_password != self.legacy_password:
            self.synced = False
        self.legacy_password = legacy_password

    def set_use(self, use, character_set):
        """
        Generic method to add or remove characters from the character set.

        :param use: should the characters be used?
        :type use: bool
        :param character_set: character set which should be inserted or removed
        :type character_set: str
        """
        s = set(self.used_characters)
        if use:
            for c in character_set:
                s.add(c)
        else:
            for c in character_set:
                if c in s:
                    s.remove(c)
        new_character_set = ""
        for c in DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
                DEFAULT_CHARACTER_SET_DIGITS + DEFAULT_CHARACTER_SET_EXTRA:
            if c in s:
                new_character_set += c
                s.remove(c)
        new_character_set += "".join(s)
        self.used_characters = new_character_set

    def use_letters(self):
        """
        Returns true if the character set contains the default set of letters at the default position and with the
        default order.

        :return: does it use letters?
        :rtype: bool
        """
        return self.used_characters[:len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE)] == \
            DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE

    def set_use_letters(self, use_letters):
        """
        If set to True the letters are moved to the default position and brought into the default order. Missing
        letters are inserted. If set to False all default letters are removed from the character set.

        :param use_letters:
        :type use_letters: bool
        """
        old_character_set = self.used_characters
        self.set_use(use_letters, DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE)
        if old_character_set != self.used_characters:
            self.synced = False

    def use_lower_case(self):
        """
        Returns true if the character set contains the default set of lower case letters at the default position and
        with the default order.

        :return: using lower case?
        :rtype: bool
        """
        return self.used_characters[:len(DEFAULT_CHARACTER_SET_LOWER_CASE)] == DEFAULT_CHARACTER_SET_LOWER_CASE

    def set_use_lower_case(self, use_lower_case):
        """
        If set to True the lower case letters are moved to the default position and brought into the default order.
        Missing lower case letters are inserted. If set to False all lower case letters are removed from the character
        set.

        :param use_lower_case:
        :type use_lower_case: bool
        """
        old_character_set = self.used_characters
        self.set_use(use_lower_case, DEFAULT_CHARACTER_SET_LOWER_CASE)
        if old_character_set != self.used_characters:
            self.synced = False

    def use_upper_case(self):
        """
        Returns true if the character set contains the default set of upper case letters at the default position and
        with the default order.

        :return: use upper case?
        :rtype: bool
        """
        return self.used_characters[
            len(DEFAULT_CHARACTER_SET_LOWER_CASE):len(
                DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE)] \
            == DEFAULT_CHARACTER_SET_UPPER_CASE

    def set_use_upper_case(self, use_upper_case):
        """
        If set to True the upper case letters are moved to the default position and brought into the default order.
        Missing upper case letters from the default set of upper case letters are inserted. If set to False all
        default upper case letters are removed from the character set.

        :param use_upper_case:
        :type use_upper_case: bool
        """
        old_character_set = self.used_characters
        self.set_use(use_upper_case, DEFAULT_CHARACTER_SET_UPPER_CASE)
        if old_character_set != self.used_characters:
            self.synced = False

    def use_digits(self):
        """
        Returns true if the character set contains digits at the default position and with the default order.

        :return: use digits?
        :rtype: bool
        """
        return self.used_characters[
            len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE):len(
                DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + DEFAULT_CHARACTER_SET_DIGITS)] \
            == DEFAULT_CHARACTER_SET_DIGITS

    def set_use_digits(self, use_digits):
        """
        If set to True the digits are moved to the default position and brought into the default order.
        Missing digits are inserted. If set to False all digits are removed from the character set.

        :param use_digits:
        :type use_digits: bool
        """
        old_character_set = self.used_characters
        self.set_use(use_digits, DEFAULT_CHARACTER_SET_DIGITS)
        if old_character_set != self.used_characters:
            self.synced = False

    def use_extra(self):
        """
        Returns true if the character set contains the special characters from the default set at the default position
        and with the default order.

        :return: use special characters?
        :rtype: bool
        """
        return self.used_characters[
            len(DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + DEFAULT_CHARACTER_SET_DIGITS):] \
            == DEFAULT_CHARACTER_SET_EXTRA

    def set_use_extra(self, use_extra):
        """
        If set to True the default special characters are moved to the default position and brought into the default
        order. Missing special characters from the default set are inserted. If set to False all special characters
        from the default set are removed from the character set.

        :param use_extra:
        :type use_extra: bool
        """
        old_character_set = self.used_characters
        s = set(self.used_characters)
        if use_extra:
            for c in DEFAULT_CHARACTER_SET_EXTRA:
                s.add(c)
        else:
            for c in list(s):
                if c not in DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
                        DEFAULT_CHARACTER_SET_DIGITS:
                    s.remove(c)
        new_character_set = ""
        for c in DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
                DEFAULT_CHARACTER_SET_DIGITS + DEFAULT_CHARACTER_SET_EXTRA:
            if c in s:
                new_character_set += c
                s.remove(c)
        new_character_set += "".join(s)
        self.used_characters = new_character_set
        if old_character_set != new_character_set:
            self.synced = False

    def use_custom_character_set(self):
        """
        Returns false if the character set is set to the default character set.

        :return: are we using a custom character set?
        :rtype: bool
        """
        return not self.used_characters == DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
            DEFAULT_CHARACTER_SET_DIGITS + DEFAULT_CHARACTER_SET_EXTRA

    @staticmethod
    def get_default_character_set():
        """
        Returns the default character set. This is completely independent of the character set stored at instances
        of this class.

        :return: the default character set
        :rtype: str
        """
        return DEFAULT_CHARACTER_SET_LOWER_CASE + DEFAULT_CHARACTER_SET_UPPER_CASE + \
            DEFAULT_CHARACTER_SET_DIGITS + DEFAULT_CHARACTER_SET_EXTRA

    def get_character_set(self):
        """
        Returns the character set as a string.

        :return: character set
        :rtype: str
        """
        return self.used_characters

    def set_custom_character_set(self, character_set):
        """
        Sets the character set to the given string. Use this method to save reordered default sets.

        :param str character_set: character set
        """
        if self.used_characters != character_set:
            self.synced = False
        self.used_characters = character_set

    @staticmethod
    def get_lower_character_set():
        """
        Returns the default lower case characters.

        :return: string with lower case characters
        :rtype: str
        """
        return DEFAULT_CHARACTER_SET_LOWER_CASE

    @staticmethod
    def get_upper_character_set():
        """
        Returns the default upper case characters.

        :return: string with upper case characters
        :rtype: str
        """
        return DEFAULT_CHARACTER_SET_UPPER_CASE

    @staticmethod
    def get_digits_character_set():
        """
        Returns the default digits characters.

        :return: string with digits characters
        :rtype: str
        """
        return DEFAULT_CHARACTER_SET_DIGITS

    def get_extra_character_set(self):
        """
        Returns the set of special characters.

        :return: set of special characters
        :rtype: str
        """
        return self.extra_characters

    def set_extra_character_set(self, extra_set):
        """
        Sets the set of special characters. This function does not check if these characters are in the whole
        character set.

        :param extra_set: string of special characters
        :type extra_set: str
        """
        if extra_set is None or len(extra_set) <= 0:
            self.extra_characters = DEFAULT_CHARACTER_SET_EXTRA
        else:
            self.extra_characters = extra_set

    def get_salt(self):
        """
        Returns the salt.

        :return: the salt
        :rtype: bytes
        """
        return self.salt

    def set_salt(self, salt):
        """
        You should normally pass bytes as a salt. For convenience this method also accepts strings which get
        UTF-8 encoded and stored in binary format. If in doubt pass bytes.

        :param salt:
        :type salt: bytes or str
        """
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
        """
        Returns the desired password length.

        :return: length
        :rtype: int
        """
        return self.length

    def set_length(self, length):
        """
        Sets the desired length.

        :param length:
        :type length: int
        """
        if self.length != length:
            self.synced = False
        self.length = length

    def get_iterations(self):
        """
        Returns the iteration count which is to be used.

        :return: iteration count
        :rtype: int
        """
        return self.iterations

    def set_iterations(self, iterations):
        """
        Sets the iteration count integer.

        :param iterations:
        :type iterations: int
        """
        if self.iterations != iterations:
            self.synced = False
        self.iterations = iterations

    def get_c_date(self):
        """
        Returns the creation date as a datetime object.

        :return: the creation date
        :rtype: datetime
        """
        return self.creation_date

    def get_creation_date(self):
        """
        Returns the creation date as string.

        :return: the creation date
        :rtype: str
        """
        return self.creation_date.strftime("%Y-%m-%dT%H:%M:%S")

    def set_creation_date(self, creation_date):
        """
        Sets the creation date passed as string.

        :param creation_date:
        :type creation_date: str
        """
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
        """
        Returns the modification date as a datetime object.

        :return: the modification date
        :rtype: datetime
        """
        return self.modification_date

    def get_modification_date(self):
        """
        Returns the modification date as string.

        :return: the modification date
        :rtype: str
        """
        return self.modification_date.strftime("%Y-%m-%dT%H:%M:%S")

    def set_modification_date(self, modification_date=None):
        """
        Sets the modification date passed as string.

        :param modification_date:
        :type modification_date: str
        """
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
        """
        Returns the notes.

        :return: the notes
        :rtype: str
        """
        if self.notes:
            return self.notes
        else:
            return ""

    def set_notes(self, notes):
        """
        Sets some note. This overwrites existing notes.

        :param notes:
        :type notes: str
        """
        if notes != self.notes:
            self.synced = False
        self.notes = notes

    def get_url(self):
        """
        Returns a url if there is one.

        :return: the url
        :rtype: str
        """
        if self.url:
            return self.url
        else:
            return ""

    def set_url(self, url):
        """
        Sets a url.

        :param url: the url
        :type url: str
        """
        if url != self.url:
            self.synced = False
        else:
            return self.url

    def get_full_template(self):
        """
        Constructs a template string with digit and semicolon.

        :return: template string
        :rtype: str
        """
        complexity = self.get_complexity()
        if complexity >= 0:
            return str(complexity) + ";" + self.get_template()
        else:
            return ""

    def calculate_template(self):
        """
        Calculates a new template based on the character set configuration and the length.
        """
        l = []
        inserted_lower = False
        inserted_upper = False
        inserted_digit = False
        inserted_extra = False
        for i in range(self.get_length()):
            if self.force_character_classes and self.use_lower_case() and not inserted_lower:
                l.append('a')
                inserted_lower = True
            elif self.force_character_classes and self.use_upper_case() and not inserted_upper:
                l.append('A')
                inserted_upper = True
            elif self.force_character_classes and self.use_digits() and not inserted_digit:
                l.append('n')
                inserted_digit = True
            elif self.force_character_classes and self.use_extra() and not inserted_extra:
                l.append('o')
                inserted_extra = True
            else:
                l.append('x')
        shuffle(l)
        self.template = ''.join(l)

    def get_template(self):
        """
        Returns the template without digit and semicolon.

        :return: template
        :rtype: str
        """
        if not self.template:
            self.calculate_template()
        return self.template

    def set_full_template(self, full_template):
        """
        Sets a template from a complete template string with digit and semicolon. This also preferences the template
        so other settings might get ignored.

        :param full_template: complete template string
        :type full_template: str
        """
        matches = re.compile("([0123456]);([aAnox]+)").match(full_template)
        if matches and len(matches.groups()) >= 2:
            self.force_character_classes = True
            self.set_complexity(int(matches.group(1)))
            self.template = matches.group(2)

    def set_complexity(self, complexity):
        """
        Sets the complexity by activating the appropriate character groups.

        :param complexity: 0, 1, 2, 3, 4, 5 or 6
        :type complexity: int
        """
        if 0 <= complexity <= 6:
            if complexity == 0:
                self.set_use_digits(True)
                self.set_use_lower_case(False)
                self.set_use_upper_case(False)
                self.set_use_extra(False)
            elif complexity == 1:
                self.set_use_digits(False)
                self.set_use_lower_case(True)
                self.set_use_upper_case(False)
                self.set_use_extra(False)
            elif complexity == 2:
                self.set_use_digits(False)
                self.set_use_lower_case(False)
                self.set_use_upper_case(True)
                self.set_use_extra(False)
            elif complexity == 3:
                self.set_use_digits(True)
                self.set_use_lower_case(True)
                self.set_use_upper_case(False)
                self.set_use_extra(False)
            elif complexity == 4:
                self.set_use_digits(False)
                self.set_use_lower_case(True)
                self.set_use_upper_case(True)
                self.set_use_extra(False)
            elif complexity == 5:
                self.set_use_digits(True)
                self.set_use_lower_case(True)
                self.set_use_upper_case(True)
                self.set_use_extra(False)
            elif complexity == 6:
                self.set_use_digits(True)
                self.set_use_lower_case(True)
                self.set_use_upper_case(True)
                self.set_use_extra(True)
        else:
            ValueError("The complexity must be in the range 0 to 6.")

    def get_complexity(self):
        """
        Returns the complexity as a digit from 0 to 6. If the character selection does not match a complexity
        group -1 is returned.

        :return: a digit from 0 to 6 or -1
        :rtype: int
        """
        if self.use_digits() and not self.use_lower_case() and \
                not self.use_upper_case() and not self.use_extra():
            return 0
        elif not self.use_digits() and self.use_lower_case() and \
                not self.use_upper_case() and not self.use_extra():
            return 1
        elif not self.use_digits() and not self.use_lower_case() and \
                self.use_upper_case() and not self.use_extra():
            return 2
        elif self.use_digits() and self.use_lower_case() and \
                not self.use_upper_case() and not self.use_extra():
            return 3
        elif not self.use_digits() and self.use_lower_case() and \
                self.use_upper_case() and not self.use_extra():
            return 4
        elif self.use_digits() and self.use_lower_case() and \
                self.use_upper_case() and not self.use_extra():
            return 5
        elif self.use_digits() and self.use_lower_case() and \
                self.use_upper_case() and self.use_extra():
            return 6
        else:
            return -1

    def is_synced(self):
        """
        Query if the synced flag is set. The flag switches to false if settings are changed.

        :return: is synced?
        :rtype: bool
        """
        return self.synced

    def set_synced(self, is_synced=True):
        """
        Sets the synced state. Call this after syncing.

        :param is_synced:
        :type is_synced: bool
        """
        self.synced = is_synced

    def to_dict(self):
        """
        Returns a dictionary with settings to be saved.

        :return: a dictionary with settings to be saved
        :rtype: dict
        """
        domain_object = {"domain": self.get_domain()}
        if self.get_url():
            domain_object["url"] = self.get_url()
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
        domain_object["extras"] = self.get_extra_character_set()
        if self.force_character_classes:
            domain_object["passwordTemplate"] = self.get_full_template()
        return domain_object

    def load_from_dict(self, loaded_setting):
        """
        Loads the setting from a dictionary.

        :param loaded_setting:
        :type loaded_setting: dict
        """
        if "url" in loaded_setting:
            self.set_url(loaded_setting["url"])
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
        if "extras" in loaded_setting:
            self.set_extra_character_set(loaded_setting["extras"])
        if "passwordTemplate" in loaded_setting:
            self.set_full_template(loaded_setting["passwordTemplate"])

    def ask_for_input(self):
        """
        Displays some input prompts for the settings properties.
        """
        self.set_username(input('Benutzername: '))
        wants_legacy_password = input('Möchten Sie ein Passwort generieren (Alternative: nur speichern)? [J/n] ')
        if wants_legacy_password in ['n', 'N', 'speichern', 'save', 'no', 'nein', 'Nein', 'No', 'Nay']:
            self.set_legacy_password(getpass.getpass('klassisches Passwort: '))
        else:
            length_str = input('Passwortlänge [' + str(self.get_length()) + ']: ')
            try:
                length = int(length_str)
                if length <= 0:
                    length = self.get_length()
            except ValueError:
                length = self.get_length()
            self.set_length(length)
            iterations_str = input('Iterationszahl [' + str(self.get_iterations()) + ']: ')
            try:
                iterations = int(iterations_str)
                if iterations <= 0:
                    iterations = self.get_iterations()
            except ValueError:
                iterations = self.get_iterations()
            self.set_iterations(iterations)

#!/usr/bin/python3
# -*- coding: utf-8 -*-

import unittest
from password_setting import PasswordSetting
import json
from base64 import b64encode


class TestPasswordSetting(unittest.TestCase):
    def test_username(self):
        s = PasswordSetting("unit.test")
        self.assertEqual("", s.get_username())
        s.set_username("Hugo")
        self.assertEqual("Hugo", s.get_username())

    def test_legacy_password(self):
        s = PasswordSetting("unit.test")
        self.assertEqual("", s.get_legacy_password())
        s.set_legacy_password("K6x/vyG9(p")
        self.assertEqual("K6x/vyG9(p", s.get_legacy_password())

    def test_character_set(self):
        s = PasswordSetting("unit.test")
        self.assertEqual("0123456789" +
                         "abcdefghijklmnopqrstuvwxyz" +
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                         "#!\"§$%&/()[]{}=-_+*<>;:.", s.get_character_set())
        s.set_extra_character_set("&=Oo0wWsS$#uUvVzZ")
        s.set_template("oxxxxxxxxx")
        self.assertEqual("&=Oo0wWsS$#uUvVzZ", s.get_character_set())
        s.set_extra_character_set(
            "abcdefghijklmnopqrstuvwxyz" +
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
            "0123456789" +
            "#!\"§$%&/()[]{}=-_+*<>;:.")
        self.assertEqual("abcdefghijklmnopqrstuvwxyz" +
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                         "0123456789" +
                         "#!\"§$%&/()[]{}=-_+*<>;:.", s.get_character_set())
        s.set_template("noxxxxxxxx")
        s.set_extra_character_set("#!\"§$%&/()[]{}=-_+*<>;:.")
        self.assertEqual("0123456789#!\"§$%&/()[]{}=-_+*<>;:.", s.get_character_set())
        s.set_template("xaxxxAxxx")
        self.assertEqual("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", s.get_character_set())

    def test_get_character_set(self):
        s = PasswordSetting("unit.test")
        self.assertEqual("c", s.get_character_set()[12])
        s.set_extra_character_set("axFLp0")
        s.set_template("xox")
        self.assertEqual(6, len(s.get_character_set()))
        self.assertEqual("F", s.get_character_set()[2])
        self.assertEqual("0", s.get_character_set()[5])

    def test_salt(self):
        s = PasswordSetting("unit.test")
        self.assertEqual(32, len(s.get_salt()))
        s.set_salt("somethingelse".encode('utf-8'))
        expected = "somethingelse".encode('utf-8')
        self.assertEqual(len(expected), len(s.get_salt()))
        for i in range(len(expected)):
            self.assertEqual(expected[i], s.get_salt()[i])

    def test_set_creation_date(self):
        s = PasswordSetting("unit.test")
        s.set_modification_date("1995-01-01T01:14:12")
        s.set_creation_date("2001-01-01T02:14:12")
        self.assertEqual("2001-01-01T02:14:12", s.get_creation_date())
        self.assertEqual("2001-01-01T02:14:12", s.get_modification_date())

    def test_set_modification_date(self):
        s = PasswordSetting("unit.test")
        s.set_creation_date("2007-01-01T02:14:12")
        s.set_modification_date("2005-01-01T01:14:12")
        self.assertEqual("2005-01-01T01:14:12", s.get_creation_date())
        self.assertEqual("2005-01-01T01:14:12", s.get_modification_date())

    def test_notes(self):
        s = PasswordSetting("unit.test")
        self.assertEqual("", s.get_notes())
        s.set_notes("Beware of the password!")
        self.assertEqual("Beware of the password!", s.get_notes())

    def test_to_json(self):
        s = PasswordSetting("unit.test")
        s.set_modification_date("2005-01-01T01:14:12")
        s.set_creation_date("2001-01-01T02:14:12")
        s.set_salt("something".encode('utf-8'))
        s.set_iterations(213)
        s.set_template("xxxxxxxxxxoxxx")
        s.set_extra_character_set("XVLCWKHGFQUIAEOSNRTDYÜÖÄPZBMJ")
        s.set_notes("Some note.")
        self.assertIn("domain", s.to_dict())
        self.assertEqual("unit.test", s.to_dict()["domain"])
        self.assertIn("cDate", s.to_dict())
        self.assertEqual("2001-01-01T02:14:12", s.to_dict()["cDate"])
        self.assertIn("mDate", s.to_dict())
        self.assertEqual("2005-01-01T01:14:12", s.to_dict()["mDate"])
        self.assertIn("salt", s.to_dict())
        self.assertEqual(str(b64encode("something".encode('utf-8')), encoding='utf-8'), s.to_dict()["salt"])
        self.assertIn("iterations", s.to_dict())
        self.assertEqual(213, s.to_dict()["iterations"])
        self.assertIn("passwordTemplate", s.to_dict())
        self.assertEqual("xxxxxxxxxxoxxx", s.to_dict()["passwordTemplate"])
        self.assertIn("extras", s.to_dict())
        self.assertEqual("XVLCWKHGFQUIAEOSNRTDYÜÖÄPZBMJ", s.to_dict()["extras"])
        self.assertIn("notes", s.to_dict())
        self.assertEqual("Some note.", s.to_dict()["notes"])

    def test_load_from_json(self):
        json_str = "{\"domain\": \"unit.test\", \"username\": \"testilinius\", " +\
                   "\"notes\": \"interesting note\", \"legacyPassword\": \"rtSr?bS,mi\", " +\
                   "\"extras\": \"AEIOUaeiou\", \"iterations\": 5341, " +\
                   "\"passwordTemplate\": \"7;xxxxoxxxxxxxxxxx\", \"salt\": \"ZmFzY2luYXRpbmc=\", " +\
                   "\"cDate\": \"2001-01-01T02:14:12\", \"mDate\": \"2005-01-01T01:14:12\"}"
        s = PasswordSetting(json.loads(json_str)["domain"])
        s.load_from_dict(json.loads(json_str))
        self.assertEquals("unit.test", s.get_domain())
        self.assertEquals("testilinius", s.get_username())
        self.assertEquals("interesting note", s.get_notes())
        self.assertEquals("rtSr?bS,mi", s.get_legacy_password())
        self.assertEquals("AEIOUaeiou", s.get_character_set())
        self.assertEquals(5341, s.get_iterations())
        self.assertEquals("xxxxoxxxxxxxxxxx", s.get_template())
        expected_salt = "fascinating".encode('utf-8')
        self.assertEqual(len(expected_salt), len(s.get_salt()))
        for i in range(len(expected_salt)):
            self.assertEqual(expected_salt[i], s.get_salt()[i])
        self.assertEquals("2001-01-01T02:14:12", s.get_creation_date())
        self.assertEquals("2005-01-01T01:14:12", s.get_modification_date())

    def test_get_template(self):
        s = PasswordSetting("unit.test")
        s.set_template("xxxaxxxxxxx")
        self.assertEqual("xxxaxxxxxxx", s.get_template())
        s.set_template("6;xxxxxxoxxxnAxxxa")
        self.assertEqual("xxxxxxoxxxnAxxxa", s.get_template())
        self.assertEqual(16, len(s.get_template()))


if __name__ == '__main__':
    unittest.main()

# coding=utf-8
"""
Test for CtSESAM class.
"""
import unittest
from password_generator import CtSesam
from password_setting import PasswordSetting
from hashlib import pbkdf2_hmac
from binascii import unhexlify


class TestPBKDF2(unittest.TestCase):
    def test_pbkdf2(self):
        expected_hash = unhexlify("2646f9ccb58d21406815bafc62245771bf80aaa080a633ff1bdd660eb44f369a89da48fb" +
                                  "041c5551a118de20cfb8b96b92e7a9945425ba889e9ad645614522eb")
        self.assertEqual(expected_hash, pbkdf2_hmac('sha512', "message".encode('utf-8'), "pepper".encode('utf-8'), 3))

    def test_pbkdf2_empty_salt(self):
        expected_hash = unhexlify("b8ec13cfc9b9d49ca1143018ce8413a962c09c0063f30a466df802897475c57f268d91cc" +
                                  "568ac1b6a9f19b1a0db10f30058fb7a453b2675010ef2b5f96487ad3")
        self.assertEqual(expected_hash, pbkdf2_hmac('sha512', "message".encode('utf-8'), b"", 3))

    def test_pbkdf2_empty_message(self):
        expected_hash = unhexlify("9dd331fc67421e1dce619cbbb517170e2dc325491d3426425630c4c01fd0eca8d8f535d6" +
                                  "b0555a2aa43efbc9141e3dd7edaef8b1278ac34eabfc2db735d992ee")
        self.assertEqual(expected_hash, pbkdf2_hmac('sha512', b"", "pepper".encode('utf-8'), 3))

    def test_pbkdf2_long_message(self):
        expected_hash = unhexlify("efc8e734ed5b5657ac220046754b7d1dbea00983f13209b1ec1d0e418e98807cba1026d3" +
                                  "ed3fa2a09dfa43c074447bf4777e70e4999d29d2c2f84dc51502a195")
        long_message = "ThisMessageIsLongerThanSixtyFourCharactersWhichLeadsToTheSituationThatTheMessageHasTo" + \
                       "BeHashedWhenCalculatingTheHmac"
        self.assertEqual(expected_hash,
                         pbkdf2_hmac('sha512', long_message.encode('utf-8'), "pepper".encode('utf-8'), 3))


class TestCtSesam(unittest.TestCase):
    def test_default(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_template("xaxnxxAoxx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("]ew26XW.X<", manager.generate(setting))

    def test_custom_character_set(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_extra_character_set(
            'abcdefghijklmnopqrstuvwxyzABCDUFGHJKLMNPQRTEVWXYZ0123456789#!"§$%&/()[]{}=-_+*<>;:.')
        setting.set_template("oxxxxxxxxx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("5#%KiEvUU7", manager.generate(setting))

    def test_custom_salt(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt(b'qanisaoerna56745678eornsiarteonstiaroenstiaeroh')
        setting.set_template("oxAxxaxxnx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual(")hN8ol<;6<", manager.generate(setting))

    def test_long(self):
        setting = PasswordSetting('some.domain')
        setting.set_salt('pepper'.encode('utf-8'))
        setting.set_template("Aanoxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk='foo'.encode('utf-8'))
        self.assertEqual("Ba0=}#K.X<$/eS0AuGjRm>(\"dnDnvZCx", manager.generate(setting))

    def test_simple_password_1(self):
        setting = PasswordSetting('ct.de')
        setting.set_extra_character_set("abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ0123456789" +
                                        "#!\"§$%&/()[]{}=-_+*<>;:.")
        setting.set_iterations(4096)
        setting.set_template("oxxxxxxxxx")
        setting.set_salt('pepper'.encode('utf-8'))
        kgk = 'test'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("f4d54b303b21ee3d8bff9c1eae6f66d90db58c0a5cc770eee322cc59d4dec65793bf8f5dec" +
                                   "717fd1404bbfacf59befa68c4ad9168bfeaa6a9e28b326a76a82bb"), manager.hash_value)
        self.assertEqual("YBVUH=sN/3", manager.generate(setting))

    def test_simple_password_2(self):
        setting = PasswordSetting('MyFavoriteDomain')
        setting.set_extra_character_set("abcdefghijklmnopqrstuvwxyzABCDEFGHJKLMNPQRTUVWXYZ")
        setting.set_iterations(8192)
        setting.set_template("oxxxxxxxxxxxxxxx")
        setting.set_salt('pepper'.encode('utf-8'))
        kgk = 'foobar'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("cb0ae7b2b7fc969770a9bfc1eef3a9afd02d2b28d6d8e9cb324f41a31392a0f800ea7e2e43" +
                                   "e847537ceb863a16a869d5e4dd6822cf3be0206440eff97dc2001c"), manager.hash_value)
        self.assertEqual("wLUwoQvKzBaYXbme", manager.generate(setting))

    def test_simple_password_1_tpl(self):
        setting = PasswordSetting('FooBar')
        setting.set_extra_character_set("#!\"$%&/()[]{}=-_+*<>;:.")
        setting.set_iterations(4096)
        setting.set_template("xxoxAxxxxxxxxxaxx")
        setting.set_salt('blahfasel'.encode('utf-8'))
        kgk = 'test'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("4e9e2503556bda7ad06cf45cab4490213becd3473845a868900fb61fa17d1c448496d11987c4" +
                                   "446d8007562029cce7f176eda4157604012a44e42add594a524e"), manager.hash_value)
        self.assertEqual("pU)VUfgJ-Ws*wgzzE", manager.generate(setting))

    def test_simple_password_2_tpl(self):
        setting = PasswordSetting('FooBar')
        setting.set_iterations(8192)
        setting.set_template("xxaxxx")
        setting.set_salt('blahfasel'.encode('utf-8'))
        kgk = 'test'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("309d504d68dc921dcece9d10c14b406673715f15782032d64229b4b42336c8ec860cd9b945" +
                                   "104824ce43720b3a088828843df4029fdb8b2314f8b5129c815949"), manager.hash_value)
        self.assertEqual("baeloh", manager.generate(setting))

    def test_simple_password_3_tpl(self):
        setting = PasswordSetting('FooBar')
        setting.set_iterations(8192)
        setting.set_template("xxAxxx")
        setting.set_salt('blahfasel'.encode('utf-8'))
        kgk = 'test'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("309d504d68dc921dcece9d10c14b406673715f15782032d64229b4b42336c8ec860cd9b9451048" +
                                   "24ce43720b3a088828843df4029fdb8b2314f8b5129c815949"), manager.hash_value)
        self.assertEqual("BAELOH", manager.generate(setting))

    def test_simple_password_4_tpl(self):
        setting = PasswordSetting('FooBar')
        setting.set_iterations(8192)
        setting.set_extra_character_set("0123456789abcdef")
        setting.set_template("xxxxxxxxxxxxxxxxxxxxxxxoxxxx")
        setting.set_salt('SALT'.encode('utf-8'))
        kgk = 'MY_T0P_5ecr57_PA55W0RD ;-)'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("4993fd21600977c6f56b833eed223dda9b1bd34294afd1db4925553099cce402abda7000a22d2c" +
                                   "fda152afcf8a3a142e55ce57a9597434a39d05ccd93a853626"), manager.hash_value)
        self.assertEqual("626358a39dcc50d93a4347959a75", manager.generate(setting))

    def test_pin(self):
        setting = PasswordSetting('Bank')
        setting.set_iterations(1)
        setting.set_extra_character_set("0123456789")
        setting.set_template("oxxx")
        setting.set_salt('pepper'.encode('utf-8'))
        kgk = 'reallysafe'.encode('utf-8')
        manager = CtSesam(domain=setting.get_domain(), username=setting.get_username(), kgk=kgk,
                          salt=setting.get_salt(), iterations=setting.get_iterations())
        self.assertEqual(unhexlify("55b5f5cdd9bf2845e339650b4f6e1398cf7fe9ceed087eb5f5bc059882723579fc8ec27443417" +
                                   "cf33c9763bafac6277fbe991bf27dd0206e78f7d9dfd574167f"), manager.hash_value)
        self.assertEqual("7809", manager.generate(setting))

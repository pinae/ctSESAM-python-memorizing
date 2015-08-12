
import tempfile
import unittest
import ctSESAM


class TestCtSESAM(unittest.TestCase):
    def setUp(self):
        self.test_config = tempfile.NamedTemporaryFile(prefix='ctSESAM_tests_', suffix=".ini")
        self.cfg = ctSESAM.SesamConfig(self.test_config.name, verbose=False)
        self.cfg.write_defaults()
        self.cfg.load_from_config()
        self.cfg.salt="pepper"

    def tearDown(self):
        self.test_config.close()

    def test_salt(self):
        self.assertEqual(self.cfg.salt, "pepper")

    def test_generate_password(self):
        password = ctSESAM.generate_password(domain="foobar.tld", master_password="12345678", cfg=self.cfg)
        self.assertEqual(password, "Kcr_1-=2fQ")
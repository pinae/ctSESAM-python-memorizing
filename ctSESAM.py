#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PasswordManager import CtSesam
from PasswordSettingsManager import PasswordSettingsManager
import getpass
import zlib

if __name__ == "__main__":
    settings_manager = PasswordSettingsManager()
    master_password = getpass.getpass(prompt='Masterpasswort: ')
    try:
        settings_manager.load_settings(master_password)
    except zlib.error:
        print("Falsches Masterpasswort. Es wurden keine Einstellungen geladen.")
    domain = input('Domain: ')
    while len(domain) < 1:
        print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
        domain = input('Domain: ')
    setting_found = False
    if domain in [dom[:len(domain)] for dom in settings_manager.get_domain_list()]:
        if domain in settings_manager.get_domain_list():
            setting_found = True
            print("Die Einstellungen für " + domain + " wurden geladen.")
        else:
            for dom in settings_manager.get_domain_list():
                if dom[:len(domain)] == domain:
                    answer = input("Für die Domain '" + dom + "' wurden Einstellungen gefunden. " +
                                   "Sollen sie geladen werden [J/n]? ")
                    if answer not in ["n", "N", "Nein", "nein", "NEIN", "NO", "No", "no", "nay", "not", "Not", "NOT"]:
                        domain = dom
                        setting_found = True
    setting = settings_manager.get_setting(domain)
    if not setting_found:
        setting.ask_for_input()
    settings_manager.set_setting(setting)
    settings_manager.store_settings(master_password)
    sesam = CtSesam()
    sesam.set_password_character_set(setting.get_character_set())
    sesam.set_salt(setting.get_salt())
    password = sesam.generate(
        master_password,
        setting.get_domain(),
        setting.get_username(),
        length=setting.get_length(),
        iterations=setting.get_iterations())
    print('Passwort: ' + password)

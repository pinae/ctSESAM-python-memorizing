#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PasswordManager import CtSesam
from PasswordSettingsManager import PasswordSettingsManager, DecryptionError
from Sync import Sync
import getpass

if __name__ == "__main__":
    syncer = Sync("https://ersatzworld.net/ctpwdgen-server/", 'inter', 'op')
    remote_blob = syncer.pull()
    master_password = getpass.getpass(prompt='Masterpasswort: ')
    settings_manager = PasswordSettingsManager()
    write_to_file = False
    remote_update_needed = False
    try:
        settings_manager.load_settings_from_file(master_password)
        remote_update_needed = settings_manager.update_from_export_data(master_password, remote_blob)
        write_to_file = True
    except DecryptionError:
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
        setting.set_username(input('Benutzername: '))
        length_str = input('Passwortlänge [10]: ')
        try:
            length = int(length_str)
            if length <= 0:
                length = 10
        except ValueError:
            length = 10
        setting.set_length(length)
        iterations_str = input('Iterationszahl [4096]: ')
        try:
            iterations = int(iterations_str)
            if iterations <= 0:
                iterations = 4096
        except ValueError:
            iterations = 4096
        remote_update_needed = True
    settings_manager.save_setting(setting)
    if write_to_file:
        settings_manager.save_settings_to_file(master_password)
    if remote_update_needed:
        syncer.push(settings_manager.get_export_data(master_password))
        settings_manager.set_all_settings_to_synced()
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

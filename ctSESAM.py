#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Main file for c't SESAM.
"""

from password_generator import CtSesam
from preference_manager import PreferenceManager
from kgk_manager import KgkManager
from password_settings_manager import PasswordSettingsManager
import zlib
import argparse
import getpass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate domain passwords from your masterpassword.")
    parser.add_argument('-n', '--no-sync',
                        action='store_const', const=True,
                        help="Do not synchronize with a server.")
    parser.add_argument('-u', '--update-sync-settings',
                        action='store_const', const=True,
                        help="Ask for server settings before synchronization.")
    parser.add_argument('--master-password', help="If not specified it will be prompted.")
    parser.add_argument('-d', '--domain', help="If not specified it will be prompted.")
    parser.add_argument('-q', '--quiet',
                        action='store_const', const=True,
                        help="Display only prompts (if necessary) and the plain password")
    args = parser.parse_args()
    if args.master_password:
        master_password = args.master_password
    else:
        master_password = getpass.getpass(prompt='Masterpasswort: ')
    preference_manager = PreferenceManager()
    kgk_manager = KgkManager(preference_manager)
    kgk_manager.decrypt_kgk(preference_manager.get_kgk_block(),
                            password=master_password.encode('utf-8'),
                            salt=preference_manager.get_salt())
    settings_manager = PasswordSettingsManager(preference_manager)
    try:
        settings_manager.load_settings(kgk_manager, master_password, args.no_sync)
        if not args.no_sync and (args.update_sync_settings or not settings_manager.sync_manager.has_settings()):
            settings_manager.sync_manager.ask_for_sync_settings()
    except zlib.error:
        print("Falsches Masterpasswort. Es wurden keine Einstellungen geladen.")
    if args.domain:
        domain = args.domain
    else:
        domain = input('Domain: ')
    while len(domain) < 1:
        print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
        domain = input('Domain: ')
    setting_found = False
    if domain in [dom[:len(domain)] for dom in settings_manager.get_domain_list()]:
        if domain in settings_manager.get_domain_list():
            setting_found = True
            if not args.quiet:
                print("Die Einstellungen für " + domain + " wurden geladen.")
        else:
            for dom in settings_manager.get_domain_list():
                if dom[:len(domain)] == domain:
                    print("Für die Domain '" + dom + "' wurden Einstellungen gefunden.")
                    answer = input("Sollen sie geladen werden [J/n]? ")
                    if answer not in ["n", "N", "Nein", "nein", "NEIN", "NO", "No", "no", "nay", "not", "Not", "NOT"]:
                        domain = dom
                        setting_found = True
    setting = settings_manager.get_setting(domain)
    if not setting_found:
        setting.ask_for_input()
    if setting_found and setting.has_username() and not args.quiet:
        print("Benutzername: " + setting.get_username())
    settings_manager.set_setting(setting)
    settings_manager.store_settings(kgk_manager)
    if setting_found and setting.has_legacy_password():
        if args.quiet:
            print(setting.get_legacy_password())
        else:
            print("klassisches Passwort: " + setting.get_legacy_password())
    else:
        sesam = CtSesam()
        sesam.set_password_character_set(setting.get_character_set())
        sesam.set_salt(setting.get_salt())
        password = sesam.generate(
            master_password,
            setting.get_domain(),
            setting.get_username(),
            setting.get_length(),
            setting.get_iterations())
        if args.quiet:
            print(password)
        else:
            print('Passwort: ' + password)

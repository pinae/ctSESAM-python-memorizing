#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PasswordManager import CtSesam
from PasswordSettingsManager import PasswordSettingsManager
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
    settings_manager = PasswordSettingsManager()
    try:
        settings_manager.load_settings(master_password, not args.no_sync, args.update_sync_settings)
        if args.update_sync_settings:
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
                    answer = input("Für die Domain '" + dom + "' wurden Einstellungen gefunden. " +
                                   "Sollen sie geladen werden [J/n]? ")
                    if answer not in ["n", "N", "Nein", "nein", "NEIN", "NO", "No", "no", "nay", "not", "Not", "NOT"]:
                        domain = dom
                        setting_found = True
    setting = settings_manager.get_setting(domain)
    if not setting_found:
        setting.ask_for_input()
    if setting_found and len(setting.get_username()) > 0:
        print("Benutzername: " + setting.get_username())
    settings_manager.set_setting(setting)
    settings_manager.store_settings(master_password)
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

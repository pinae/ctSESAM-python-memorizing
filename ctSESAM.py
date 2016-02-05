#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Main file for c't SESAM.
"""

from password_generator import CtSesam
from preference_manager import PreferenceManager
from kgk_manager import KgkManager
from password_settings_manager import PasswordSettingsManager
from base64 import b64decode
import argparse
import getpass


def create_settings_manager(kgk_mng):
    preference_mng = PreferenceManager()
    kgk_mng.set_preference_manager(preference_mng)
    kgk_mng.decrypt_kgk(preference_mng.get_kgk_block(),
                        password=master_password.encode('utf-8'),
                        salt=preference_mng.get_salt())
    return PasswordSettingsManager(preference_mng), preference_mng


def decrypt_remote_settings(kgk_mng, settings_mng):
    remote_kgk_manager = KgkManager()
    remote_kgk_manager.update_from_blob(master_password.encode('utf-8'), b64decode(data))
    if kgk_exists and remote_kgk_manager.has_kgk() and kgk_mng.has_kgk() and \
       kgk_mng.get_kgk() != remote_kgk_manager.get_kgk():
        print("Lokal und auf dem Server gibt es unterschiedliche KGKs. Das ist ein Problem!")
    else:
        if not kgk_exists:
            kgk_mng = remote_kgk_manager
            kgk_mng.set_preference_manager(preference_manager)
            kgk_mng.store_local_kgk_block()
        settings_mng.update_from_export_data(remote_kgk_manager, b64decode(data))
        print("Verbindung erfolgreich getestet.")


def get_domain(cmd_opt_domain):
    if cmd_opt_domain:
        domain = cmd_opt_domain
    else:
        domain = input('Domain: ')
    while len(domain) < 1:
        print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
        domain = input('Domain: ')
    password_setting_found = False
    if domain in [dom[:len(domain)] for dom in settings_manager.get_domain_list()]:
        if domain in settings_manager.get_domain_list():
            password_setting_found = True
            if not args.quiet:
                print("Die Einstellungen für " + domain + " wurden geladen.")
        else:
            for dom in settings_manager.get_domain_list():
                if dom[:len(domain)] == domain:
                    print("Für die Domain '" + dom + "' wurden Einstellungen gefunden.")
                    answer = input("Sollen sie geladen werden [J/n]? ")
                    if answer not in ["n", "N", "Nein", "nein", "NEIN", "NO", "No", "no", "nay", "not", "Not", "NOT"]:
                        domain = dom
                        password_setting_found = True
    return settings_manager.get_setting(domain), password_setting_found


def print_legacy_password(password_setting, quiet):
    if quiet:
        print(password_setting.get_legacy_password())
    else:
        print("klassisches Passwort: " + password_setting.get_legacy_password())


def print_generated_password(password_setting, kgk, quiet):
    sesam = CtSesam(password_setting.get_domain(),
                    password_setting.get_username(),
                    kgk,
                    password_setting.get_salt(),
                    password_setting.get_iterations())
    password = sesam.generate(password_setting)
    if quiet:
        print(password)
    else:
        print('Passwort: ' + password)

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
    kgk_manager = KgkManager()
    settings_manager, preference_manager = create_settings_manager(kgk_manager)
    kgk_exists = len(preference_manager.get_kgk_block()) == 112
    try:
        settings_manager.load_settings(kgk_manager, master_password, args.no_sync)
        if not args.no_sync and (args.update_sync_settings or not settings_manager.sync_manager.has_settings()):
            settings_manager.sync_manager.ask_for_sync_settings()
            print("Teste die Verbindung...")
            pull_successful, data = settings_manager.sync_manager.pull()
            if pull_successful and len(data) > 0:
                decrypt_remote_settings(kgk_manager, settings_manager)
            else:
                print("Es konnte keine Verbindung aufgebaut werden.")
    except ImportError: #ValueError:
        print("Falsches Masterpasswort. Es wurden keine Einstellungen geladen.")
    setting, setting_found = get_domain(args.domain)
    if not setting_found:
        setting.ask_for_input()
    if setting_found and setting.has_username() and not args.quiet:
        print("Benutzername: " + setting.get_username())
    settings_manager.set_setting(setting)
    settings_manager.store_settings(kgk_manager)
    if setting_found and setting.has_legacy_password():
        print_legacy_password(setting, args.quiet)
    else:
        print_generated_password(setting, kgk_manager.get_kgk(), args.quiet)

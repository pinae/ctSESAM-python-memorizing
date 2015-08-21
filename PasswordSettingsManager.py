#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import json
from datetime import datetime
from PasswordSetting import PasswordSetting
from Crypter import Crypter
from Packer import Packer
from base64 import b64decode, b64encode

PASSWORD_SETTINGS_FILE = os.path.expanduser('~/.ctSESAM.pws')


class PasswordSettingsManager(object):
    """
    Use this class to manage password settings. It can save the settings locally to the settings file and it can
    export them to be sent to a sync server.
    """
    def __init__(self, settings_file=PASSWORD_SETTINGS_FILE):
        self.settings_file = settings_file
        self.remote_data = None
        self.settings = []

    def load_settings_from_file(self, password):
        """
        This loads the saved settings. It is a good idea to call this method the minute you have a password.

        :param str password:
        """
        if os.path.isfile(self.settings_file):
            file = open(self.settings_file, 'br')
            data = file.read()
            crypter = Crypter(data[:32], password)
            saved_settings = json.loads(str(Packer.decompress(crypter.decrypt(data[32:])), encoding='utf-8'))
            for domain_name in saved_settings['settings'].keys():
                data_set = saved_settings['settings'][domain_name]
                found = False
                i = 0
                while i < len(self.settings):
                    setting = self.settings[i]
                    if setting.get_domain() == domain_name:
                        found = True
                        if datetime.strptime(data_set['mDate'], "%Y-%m-%dT%H:%M:%S") > setting.get_m_date():
                            setting.load_from_dict(data_set)
                            setting.set_synced(setting.get_domain() in saved_settings['synced'])
                    i += 1
                if not found:
                    new_setting = PasswordSetting(domain_name)
                    new_setting.load_from_dict(data_set)
                    new_setting.set_synced(new_setting.get_domain() in saved_settings['synced'])
                    self.settings.append(new_setting)
            file.close()

    # noinspection PyUnresolvedReferences
    def save_settings_to_file(self, password):
        """
        This actually saves the settings to a file on the disk. The file is encrypted so you need to supply the
        password.

        :param str password:
        """
        salt = os.urandom(32)
        crypter = Crypter(salt, password)
        file = open(self.settings_file, 'bw')
        file.write(salt + crypter.encrypt(Packer.compress(json.dumps(self.get_settings_as_dict()))))
        file.close()
        try:
            import win32con
            import win32api
            win32api.SetFileAttributes(self.settings_file, win32con.FILE_ATTRIBUTE_HIDDEN)
        except ImportError:
            pass

    def get_setting(self, domain):
        """
        This function always returns a setting. If no setting was stored for the given domain a new PasswordSetting
        object is created.

        :param str domain:
        :return: a setting object
        :rtype: PasswordSetting
        """
        for setting in self.settings:
            if setting.get_domain() == domain:
                return setting
        setting = PasswordSetting(domain)
        self.settings.append(setting)
        return setting

    def save_setting(self, setting):
        """
        This saves the supplied setting only in memory. Call save_settings_to_file if you want to have it saved to
        disk.

        :param PasswordSetting setting: the setting which should be saved
        """
        for i, existing_setting in enumerate(self.settings):
            if existing_setting.get_domain() == setting.get_domain():
                self.settings.pop(i)
        self.settings.append(setting)

    def delete_setting(self, setting):
        """
        This removes the setting from the internal list. Call save_settings_to_file if you want to have the change
        saved to disk.

        :param PasswordSetting setting:
        """
        i = 0
        while i < len(self.settings):
            existing_setting = self.settings[i]
            if existing_setting.get_domain() == setting.get_domain():
                self.settings.pop(i)
            else:
                i += 1

    def get_domain_list(self):
        """
        This gives you a list of saved domains.

        :return: a list of domain names
        :rtype: [str]
        """
        return [setting.get_domain() for setting in self.settings]

    def get_settings_as_dict(self):
        """
        Constructs a dictionary with a list of settings (no PasswordSetting objects but dicts) and a list of
        domain names of synced domains.

        :return: a dictionary
        :rtype: dict
        """
        settings_list = {'settings': {}, 'synced': []}
        for setting in self.settings:
            settings_list['settings'][setting.get_domain()] = setting.to_dict()
            if setting.is_synced():
                settings_list['synced'].append(setting.get_domain())
        return settings_list

    def get_export_data(self, password):
        """
        This gives you a base64 encoded string of encrypted settings data (the blob).

        :param str password:
        :return: encrypted settings blob
        :rtype: str
        """
        settings_list = self.get_settings_as_dict()['settings']
        if self.remote_data:
            for domain_name in self.remote_data.keys():
                data_set = self.remote_data[domain_name]
                if 'deleted' in data_set and data_set['deleted']:
                    for i, setting_dict in enumerate(settings_list):
                        if setting_dict['domain'] == setting_dict['domain'] and datetime.strptime(
                                data_set['mDate'], "%Y-%m-%dT%H:%M:%S") > datetime.strptime(
                                setting_dict['mDate'], "%Y-%m-%dT%H:%M:%S"):
                            settings_list[i] = data_set
                if domain_name not in settings_list.keys():
                    settings_list[domain_name] = {
                        'mDate': datetime.now(),
                        'deleted': True
                    }
        salt = os.urandom(32)
        crypter = Crypter(salt, password)
        return b64encode(b'\x00' + salt + crypter.encrypt(Packer.compress(json.dumps(settings_list))))

    def update_from_export_data(self, password, data):
        """
        This takes a base64 encoded string of encrypted settings (a blob) and updates the internal list of settings.

        :param str password: the masterpassword
        :param str data: base64 encoded data
        """
        binary_data = b64decode(data)
        data_version = binary_data[:1]
        if data_version == b'\x00':
            encryption_salt = binary_data[1:33]
            encrypted_data = binary_data[:33]
            crypter = Crypter(encryption_salt, password)
            self.remote_data = json.loads(str(Packer.decompress(crypter.decrypt(encrypted_data)), encoding='utf-8'))
            update_remote = False
            for domain_name in self.remote_data.keys():
                data_set = self.remote_data[domain_name]
                found = False
                i = 0
                while i < len(self.settings):
                    setting = self.settings[i]
                    if setting.get_domain() == domain_name:
                        found = True
                        if datetime.strptime(data_set['mDate'], "%Y-%m-%dT%H:%M:%S") > setting.get_m_date():
                            if 'deleted' in data_set and data_set['deleted']:
                                self.settings.pop(i)
                            else:
                                setting.load_from_dict(data_set)
                                setting.set_synced(True)
                                i += 1
                        else:
                            i += 1
                            update_remote = True
                    else:
                        i += 1
                if not found:
                    new_setting = PasswordSetting(domain_name)
                    new_setting.load_from_dict(data_set)
                    new_setting.set_synced(True)
                    self.settings.append(new_setting)
            for setting in self.settings:
                found = False
                for domain_name in self.remote_data.keys():
                    data_set = self.remote_data[domain_name]
                    if setting.get_domain() == domain_name:
                        found = True
                        if setting.get_m_date() >= datetime.strptime(data_set['mDate'], "%Y-%m-%dT%H:%M:%S"):
                            update_remote = True
                if not found:
                    update_remote = True
            return update_remote
        else:
            print("Unknown data format version! Could not update.")
            return False

    def set_all_settings_to_synced(self):
        """
        Convenience function for marking all saved settings as synced. Call this after a successful update at the
        sync server.
        """
        for setting in self.settings:
            setting.set_synced(True)

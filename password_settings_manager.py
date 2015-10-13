#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
The PasswordSettingsManager handles the settings and manages storage and synchronization.
"""

import json
import struct
from datetime import datetime
from password_setting import PasswordSetting
from crypter import Crypter
from packer import Packer
from sync_manager import SyncManager
from base64 import b64decode, b64encode
from kgk_manager import KgkManager


class PasswordSettingsManager:
    """
    Use this class to manage password settings. It can save the settings locally to the settings file and it can
    export them to be sent to a sync server.

    :param preference_manager: a PreferenceManager object
    :type preference_manager: PreferenceManager
    """
    def __init__(self, preference_manager):
        self.preference_manager = preference_manager
        self.remote_data = None
        self.settings = []
        self.sync_manager = SyncManager()
        self.update_remote = False

    @staticmethod
    def get_settings_crypter(kgk_manager):
        """
        Creates a settings crypter

        :param kgk_manager: a kgk manager
        :type kgk_manager: KgkManager
        :return: Crypter for settings
        :rtype: Crypter
        """
        return Crypter(Crypter.create_key(kgk_manager.get_kgk(), kgk_manager.get_salt2()) + kgk_manager.get_iv2())

    def load_local_settings(self, kgk_manager):
        """
        This loads the saved settings. It is a good idea to call this method the minute you have a kgk manager.

        :param kgk_manager: kgk manager
        :type kgk_manager: KgkManager
        """
        encrypted_settings = self.preference_manager.get_settings_data()
        if len(encrypted_settings) < 40:
            return
        settings_crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        decrypted_settings = settings_crypter.decrypt(encrypted_settings)
        sync_settings_len = struct.unpack('!I', decrypted_settings[0:4])[0]
        if sync_settings_len > 0:
            self.sync_manager.load_binary_sync_settings(decrypted_settings[4:4+sync_settings_len])
        if len(decrypted_settings) < sync_settings_len+44:
            raise ValueError("The decrypted settings are too short.")
        decompressed_settings = Packer.decompress(decrypted_settings[4+sync_settings_len:])
        if len(decompressed_settings) <= 0:
            raise PermissionError("Wrong password: The settings could not decompress.")
        saved_settings = json.loads(str(decompressed_settings, encoding='utf-8'))
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

    def store_local_settings(self, kgk_manager):
        """
        This actually saves the settings to a file on the disk. The file is encrypted so you need to supply the
        password.

        :param kgk_manager: kgk manager
        :type kgk_manager: KgkManager
        """
        kgk_manager.fresh_salt2()
        kgk_manager.fresh_iv2()
        settings_crypter = PasswordSettingsManager.get_settings_crypter(kgk_manager)
        sync_settings = self.sync_manager.get_binary_sync_settings()
        self.preference_manager.store_settings_data(settings_crypter.encrypt(
            struct.pack('!I', len(sync_settings)) + sync_settings +
            Packer.compress(json.dumps(self.get_settings_as_dict()))))
        kgk_manager.store_local_kgk_block()

    def load_settings(self, kgk_manager, password, no_sync=False):
        """
        Loads settings from local file and from a sync server if possible.

        :param kgk_manager: kgk manager
        :type kgk_manager: KgkManager
        :param password: the masterpassword
        :type password: str
        :param no_sync: skip the sync update?
        :type no_sync: bool
        """
        self.load_local_settings(kgk_manager)
        if not no_sync:
            if self.sync_manager.has_settings():
                pull_successful, data = self.sync_manager.pull()
                if pull_successful and len(data) > 0:
                    remote_kgk_manager = KgkManager()
                    remote_kgk_manager.update_from_blob(password.encode('utf-8'), b64decode(data))
                    if remote_kgk_manager.has_kgk() and kgk_manager.get_kgk() != remote_kgk_manager.get_kgk():
                        raise ValueError("KGK mismatch! This are not your settings!")
                    self.update_from_export_data(remote_kgk_manager, b64decode(data))
                else:
                    print("Sync failed: No connection to the server.")

    def get_setting(self, domain):
        """
        This function always returns a setting. If no setting was stored for the given domain a new PasswordSetting
        object is created.

        :param domain: The "domain" is the identifier of a settings object.
        :type domain: str
        :return: a setting object
        :rtype: PasswordSetting
        """
        for setting in self.settings:
            if setting.get_domain() == domain:
                return setting
        setting = PasswordSetting(domain)
        self.settings.append(setting)
        return setting

    def set_setting(self, setting):
        """
        This saves the supplied setting only in memory. Call save_settings_to_file if you want to have it saved to
        disk.

        :param PasswordSetting setting: the setting which should be saved
        """
        for i, existing_setting in enumerate(self.settings):
            if existing_setting.get_domain() == setting.get_domain():
                self.settings.pop(i)
        self.settings.append(setting)
        self.update_remote = True

    def delete_setting(self, setting):
        """
        This removes the setting from the internal list. Call save_settings_to_file if you want to have the change
        saved to disk.

        :param setting: PasswordSetting object
        :type setting: PasswordSetting
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
        settings_dict = {'settings': {}, 'synced': []}
        for setting in self.settings:
            settings_dict['settings'][setting.get_domain()] = setting.to_dict()
            if setting.is_synced():
                settings_dict['synced'].append(setting.get_domain())
        return settings_dict

    def get_export_data(self, kgk_manager):
        """
        This gives you a base64 encoded string of encrypted settings data (the blob).

        :param kgk_manager: kgk manager
        :type kgk_manager: KgkManager
        :return: encrypted settings blob
        :rtype: str
        """
        kgk_block = kgk_manager.get_fresh_encrypted_kgk()
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
        settings_crypter = self.get_settings_crypter(kgk_manager)
        return b64encode(b'\x01' + kgk_manager.get_kgk_crypter_salt() + kgk_block + settings_crypter.encrypt(
            Packer.compress(json.dumps(settings_list))))

    def update_from_export_data(self, kgk_manager, blob):
        """
        Call this method to pull settings from the sync server.

        :param kgk_manager: the kgk manager used for the decryption
        :type kgk_manager: KgkManager
        :param blob: the export data
        :type blob: bytes
        """
        if not blob[0] == 1:
            print("Version error: Wrong data format. Could not import anything.")
            return True
        settings_crypter = self.get_settings_crypter(kgk_manager)
        decrypted_settings = settings_crypter.decrypt(blob[145:])
        if len(decrypted_settings) <= 0:
            print("Wrong password.")
            return False
        self.remote_data = json.loads(str(Packer.decompress(decrypted_settings), encoding='utf-8'))
        self.update_remote = False
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
                            self.update_remote = True
                            i += 1
                    else:
                        i += 1
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
                        self.update_remote = True
            if not found:
                self.update_remote = True
        self.store_local_settings(kgk_manager)
        return self.update_remote

    def store_settings(self, kgk_manager):
        """
        Stores settings locally and remotely.

        :param kgk_manager: the kgk manager used for the encryption
        :type kgk_manager: KgkManager
        """
        self.store_local_settings(kgk_manager)
        self.update_sync_server_if_necessary(kgk_manager)

    def update_sync_server_if_necessary(self, kgk_manager):
        """
        Checks if the sync server needs to be updated. If necessary it does a push.

        :param kgk_manager: the kgk manager used for the encryption
        :type kgk_manager: KgkManager
        """
        if self.update_remote:
            if self.sync_manager.push(self.get_export_data(kgk_manager)):
                self.set_all_settings_to_synced()

    def set_all_settings_to_synced(self):
        """
        Convenience function for marking all saved settings as synced. Call this after a successful update at the
        sync server.
        """
        for setting in self.settings:
            setting.set_synced(True)

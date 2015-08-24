#!/usr/bin/python3
# -*- coding: utf-8 -*-

from Sync import Sync
from Packer import Packer
import json


class SyncManager(object):
    """
    Synchronization manager. This initializes and stores settings and handles the Sync object.
    """
    def __init__(self):
        self.server_address = ""
        self.username = ""
        self.password = ""
        self.sync = None

    def get_binary_sync_settings(self):
        """
        returns packed sync settings

        :return: binary settings
        :rtype: bytes
        """
        if self.sync:
            return Packer.compress(json.dumps({
                "server-address": self.server_address,
                "username": self.username,
                "password": self.password
            }).encode('utf-8'))
        else:
            return b''

    def load_binary_sync_settings(self, data):
        """
        loads sync settings

        :param bytes data: packed json data of sync settings
        """
        settings_dict = json.loads(str(Packer.decompress(data), encoding='utf-8'))
        if "server-address" in settings_dict and "username" in settings_dict and "password" in settings_dict:
            self.server_address = settings_dict["server-address"]
            self.username = settings_dict["username"]
            self.password = settings_dict["password"]
            self.create_sync()
        else:
            print("Sync settings konnten nicht geladen werden.")

    def ask_for_sync_settings(self):
        """
        Ask the user for sync settings: Asks for server-URL, username and password.
        """
        print("Bitte geben Sie die Einstellungen für Ihren Synchronisations-Server an...")
        self.server_address = input("URL: ")
        self.username = input("Benutzername: ")
        self.password = input("Passwort: ")
        self.create_sync()
        if len(self.sync.pull()) > 0:
            print("Verbindung erfolgreich getestet.")
        else:
            print("Es konnte keine Verbindung aufgebaut werden.")

    def create_sync(self):
        """
        creates a sync object.
        """
        self.sync = Sync(self.server_address, self.username, self.password)

    def pull(self):
        """
        pulls data from the sync server. Returns an empty string if no connection is possible.

        :return: pulled base64 data
        :rtype: str
        """
        if self.sync:
            return self.sync.pull()
        else:
            return ''

    def push(self, data):
        """
        pushes data to the sync server. If the push fails an error message is displayed.

        :param str data: base64 data
        """
        if self.sync:
            if not self.sync.push(data):
                print("Synchronisation fehlgeschlagen.")
        else:
            print("Sie haben keine gültigen Einstellungen für den sync server.")

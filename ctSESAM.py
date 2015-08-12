#!/usr/bin/python3
# -*- coding: utf-8 -*-

from PasswordManager import CtSesam

if __name__ == "__main__":
    master_password = input('Masterpasswort: ')
    domain = input('Domain: ')
    while len(domain) < 1:
        print('Bitte gib eine Domain an, für die das Passwort generiert werden soll.')
        domain = input('Domain: ')
    username = input('Benutzername: ')
    sesam = CtSesam()
    password = sesam.generate(master_password, domain, username, length=10, iterations=4096)
    print('Passwort: ' + password)

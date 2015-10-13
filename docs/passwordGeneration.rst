
Password generation
===================

c't SESAM uses an encrypted secret to generate your passwords: the kgk (Key-Generation-Key). This trick enables you
to change your masterpassword and makes sure that the secret used for the calculation of passwords is 64 bytes.

The kgk is stored and decrypted in the ``KgkManager`` class:

.. default-domain:: py
.. automodule:: kgk_manager
   :members:

The encrypted kgk, and the settings are stored in the hidden file ``.ctSESAM.pws`` in your home directory. Reading
and writing of this file is handled by the ``PreferenceManager``:

.. automodule:: preference_manager
   :members:

Passwords are generated with the ``PasswordManager`` class:

.. automodule:: password_generator
   :members:
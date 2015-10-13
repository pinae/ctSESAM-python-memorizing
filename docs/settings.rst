
Managing settings
=================

Settings are stored as ``PasswordSetting`` objects.

.. default-domain:: py
.. automodule:: password_setting
   :members:

The ``PasswordSettingsManager`` saves and manages the ``PasswordSetting`` objects.

.. automodule:: password_settings_manager
   :members:

It uses a ``Packer`` to compress data for storage and a ``Crypter`` to encrypt it.

.. automodule:: packer
   :members:

.. automodule:: crypter
   :members:

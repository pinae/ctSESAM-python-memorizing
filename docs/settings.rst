
Managing settings
=================

Settings are stored as ``PasswordSetting`` objects.

.. default-domain:: py
.. automodule:: PasswordSetting
   :members:

The ``PasswordSettingsManager`` saves and manages the ``PasswordSetting`` objects.

.. automodule:: PasswordSettingsManager
   :members:

It uses a ``Packer`` to compress data for storage and a ``Crypter`` to encrypt it.

.. automodule:: Packer
   :members:

.. automodule:: Crypter
   :members:

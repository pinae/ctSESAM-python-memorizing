
Synchronisation
===============

ctSESAM can synchronize your password settings with a ctSESAM-Server_. The exact protocol is specified in the Wiki_.

.. _ctSESAM-Server: https://github.com/ola-ct/ctSESAM-server
.. _Wiki: https://github.com/ola-ct/ctSESAM-server/wiki

Basic communication part is implemented in the ``Sync`` class.

.. automodule:: sync
   :members:

This class is wrapped by a ``SyncManager`` which handles the settings management for the server connection.

.. automodule:: sync_manager
   :members:

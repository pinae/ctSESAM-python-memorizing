This is a command line Python version of the c't password manager which is extended to save password settings locally.

[![License](https://img.shields.io/badge/license-GPLv3-blue.svg "read the terms of the GPLv3")](http://choosealicense.com/licenses/gpl-3.0/)
[![Documentation](https://readthedocs.org/projects/ctsesam-python-memorizing/badge/ "go to the documentation")](http://ctsesam-python-memorizing.readthedocs.org/en/latest)
[![Build Status](https://travis-ci.org/pinae/ctSESAM-python-memorizing.svg?branch=master)](https://travis-ci.org/pinae/ctSESAM-python-memorizing)
[![Code Health](https://landscape.io/github/pinae/ctSESAM-python-memorizing/master/landscape.svg?style=flat)](https://landscape.io/github/pinae/ctSESAM-python-memorizing/master)


What is c't SESAM?
==================

c't SESAM is a password manager which calculates passwords from masterpasswords and domains using PBKDF2. There
are compatible versions of this software for different platforms. This is the the console
version written in Python.

Dependencies
------------

If you want to use a virtual environment execute the following commands in the source directory:

```shell script
python3 -m venv env
source env/bin/activate
pip install -U pip wheel
``` 

In all cases install the dependencie named in `requirements.txt`:

```shell script
pip install -r requirements.txt
```

Usage
-----

Get Usage instructions with `--help`:

```shell script
$ python ctSESAM.py --help
usage: ctSESAM.py [-h] [-n] [-u] [--master-password MASTER_PASSWORD]
                  [-d DOMAIN] [-q]

Generate domain passwords from your masterpassword.

optional arguments:
  -h, --help            show this help message and exit
  -n, --no-sync         Do not synchronize with a server.
  -u, --update-sync-settings
                        Ask for server settings before synchronization.
  --master-password MASTER_PASSWORD
                        If not specified it will be prompted.
  -d DOMAIN, --domain DOMAIN
                        If not specified it will be prompted.
  -q, --quiet           Display only prompts (if necessary) and the plain
                        password
```

Start normally with:

```shell script
python ctSESAM.py
```

Running tests
-------------

First install `pytest`:

```shell script
pip install pytest
```

Run the tests with:

```shell script
python3 -m pytest
```

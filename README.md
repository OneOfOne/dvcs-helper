dvcs-helper
===========

A helper to (dumb)-sync DVCS repos over php/ftp.
The code is under the Apache License v2.0.

>	Copyright 2012 Ahmed (OneOfOne) Wahed
>
>	Licensed under the Apache License, Version 2.0 (the "License");
>	you may not use this file except in compliance with the License.
>	You may obtain a copy of the License at
>
>		http://www.apache.org/licenses/LICENSE-2.0
>
>	Unless required by applicable law or agreed to in writing, software
>	distributed under the License is distributed on an "AS IS" BASIS,
>	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
>	See the License for the specific language governing permissions and
>	limitations under the License.

Features
--------

* Supports uploading files using the php helper and/or ftp, or both in the same time.
* Uses threads to upload multiple files at the same time.
* Uses gzip to lower the bandwidth.
* The php helper is compatible with php 5.2, the python client is compatible with python 2.7 / 3.2.
* More to come...
* It works for me *™*

Bugs
----

* For testing purposes there isn't that much error handling.
* Haven't ran into any bugs yet, it does what I need it to do
* Doesn't handle renaming or deleting of files
* Doesn't support atomic pushes *_yet_*
* While the code is straight forward, it is badly commented.

Installation
------------

```bash
-> git clone https://github.com/OneOfOne/dvcs-helper.git
# It's been only tested with Python 2.7 and Python 3.2, and it works on both.
# for mercurial :
 -> echo '[alias]\nr = !python /path/to/dvcs-helper/dvcs-helper.py $@' >> ~/.hgrc
# for git :
 -> echo '[alias]\nr = !python /path/to/dvcs-helper/dvcs-helper.py' >> ~/.gitconfig
```

Example Usage
-------------

```bash
 -> cd ~/path/to/git-or-hg-repos
 -> hg r --help
 -> hg r config --help
#default save path is $PWD/.dvcs-helper
 -> hg r config --url http://example.com/helper.php
				--ftp ftp://user:pass@example.com/path/to/htdocs
			--base local/htdocs/path/under/vcs
			-w
 -> hg r php --help
# defaults to $PWD/helper.php
 -> hg r php -w
 -> hg r push --force helper.php
 -> hg r status
Checking 4 file(s) for changes...
nothing changed
#assuming php has no write access to the root of htdocs, it will push using ftp
 -> hg r push dvcs-helper.py
Checking 1 file(s) for changes...
Pushing 1 file(s):
 tid | method | file                                                         | status
 t01 |  ftp   | dvcs-helper.py                                               | success
#using force since the local file and remote file are the same
 -> hg r pull -f dvcs-helper.py
Checking 1 file(s) for changes...
Pushing 1 file(s):
 tid | method | file                                                         | status
 t01 |  php   | dvcs-helper.py                                               | success
```

Example .dvcs-helper
--------------------

```ini
url = http://localhost/helper.php
ftp = ftp://oneofone:pass@localhost/httpdocs/
# my repo structure is :
# root/
#      random files
#      site/ #where the http-related files are
# uncomment if your http files aren't under a sub-folder
#base =
base = htdocs/
# number of threads to use for pushing / pulling
threads = 4
# method can be ftp, http or auto, auto will try to push using http if it can,
# otherwise will use ftp
method = auto
# used internally
dvcs = hg
# the auth key used with the php helper
auth = dvcs-helper:0.8:1265888533.255733
```

WARNING
=======

## This script works for me ™
### I'm not responsible if it sets your server on fire,
### kills your cats or turns your dead dog into a zombie.
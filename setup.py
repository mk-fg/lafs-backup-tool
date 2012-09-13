#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.md')).read()
except IOError: readme = ''

setup(

	name = 'cloud-crypt-diff-backup',
	version = '12.09.1',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'backup encryption incremental diff'
		' rsync cloud free skydrive google drive dropbox',
	url = 'http://github.com/mk-fg/cloud-crypt-diff-backup',

	description = 'Tool to securely push incremental'
		' (think "rsync --link-dest") backups to cloud storage services',
	long_description = readme,

	classifiers = [
		'Development Status :: 4 - Beta',
		'Environment :: Console',
		'Environment :: No Input/Output (Daemon)',
		'Intended Audience :: Developers',
		'Intended Audience :: End Users/Desktop',
		'Intended Audience :: System Administrators',
		'License :: OSI Approved',
		'Operating System :: POSIX',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Internet',
		'Topic :: Security',
		'Topic :: System :: Archiving :: Backup',
		'Topic :: System :: Archiving :: Compression',
		'Topic :: Utilities' ],

	install_requires = ['layered-yaml-attrdict-config'],

	packages = find_packages(),
	include_package_data = True,

	package_data = {'ccdb': ['core.yaml']},
	entry_points = dict(console_scripts=[
		'ccdb = ccdb.core:main' ]) )

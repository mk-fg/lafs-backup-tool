#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.md')).read()
except IOError: readme = ''

setup(

	name = 'lafs-backup-tool',
	version = '12.10.0',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'backup encryption incremental'
		' deduplication tahoe-lafs tahoe lafs rsync cloud raic free xz',
	url = 'http://github.com/mk-fg/lafs-backup-tool',

	description = 'Tool to securely push incremental'
		' (think "rsync --link-dest") backups to tahoe-lafs.',
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

	install_requires = ['Twisted', 'layered-yaml-attrdict-config', 'pyliblzma'],

	packages = find_packages(),
	include_package_data = True,

	package_data = {'lafs_backup': ['core.yaml']},
	entry_points = dict(console_scripts=[
		'lafs-backup = lafs_backup.core:main' ]) )

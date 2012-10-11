#!/usr/bin/env python

from setuptools import setup, find_packages
import os

pkg_root = os.path.dirname(__file__)

# Error-handling here is to allow package to be built w/o README included
try: readme = open(os.path.join(pkg_root, 'README.md')).read()
except IOError: readme = ''

import lafs_backup.meta

# Workaround for a weird issue with absolute paths in cffi-0.4
cwd, ext_modules = os.getcwd(), ['CStrACL', 'CStrCaps']
for i,ext in enumerate(ext_modules):
	ext = ext_modules[i] = getattr(
		lafs_backup.meta, ext )().ffi.verifier.get_extension()
	for i, src in enumerate(ext.sources):
		if src.startswith(cwd):
			ext.sources[i] = src[len(cwd):].lstrip(os.sep)


setup(

	name = 'lafs-backup-tool',
	version = '12.10.1',
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

	install_requires = ['Twisted', 'layered-yaml-attrdict-config', 'pyliblzma', 'cffi'],

	packages = find_packages(),
	include_package_data = True,
	zip_safe = False,

	ext_modules = ext_modules,

	package_data = {'lafs_backup': ['core.yaml']},
	entry_points = dict(console_scripts=[
		'lafs-backup-tool = lafs_backup.core:main' ]) )

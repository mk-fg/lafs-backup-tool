#!/usr/bin/env python
#-*- coding: utf-8 -*-

import itertools as it, operator as op, functools as ft
from glob import glob
from os.path import join, dirname, basename
from collections import defaultdict
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import os, sys, re, types, anydbm

from twisted.internet import reactor, defer

is_str = lambda obj,s=types.StringTypes: isinstance(obj, s)

try: from lafs_backup import http
except ImportError:
	# Make sure it works from a checkout
	if isdir(join(dirname(__file__), 'lafs_backup'))\
			and exists(join(dirname(__file__), 'setup.py')):
		sys.path.insert(0, dirname(__file__))
		from lafs_backup import http

import logging
log = logging.getLogger(__name__)



class LAFSBackup(object):

	def __init__(self, conf):
		self.log = logging.getLogger('misc')
		self.conf = conf
		conf.filter = list(
			( ('-', re.compile(pat))
				if is_str(pat) else (pat[0], re.compile(pat[1])) )
			for pat in conf.filter )
		self.dentry_cache = anydbm.open(conf.source.dentry_cache, 'c')
		self.http = http.HTTPClient(**conf.http)


	def pick_path(self):
		paths = glob(self.conf.source.path)
		if not paths: return None
		if self.conf.source.pick_policy != 'alphasort_last':
			raise NotImplementedError( 'source.pick_policy'
				' {!r} is not implemented.'.format(self.conf.source.pick_policy) )
		return sorted(paths, reverse=True)[0]


	def get_meta(self, path):
		fstat = os.lstat(path)
		meta = dict(uid=fstat.st_uid, gid=fstat.st_gid)
		try: meta['caps'] = strcaps_get(path)
		except OSError: pass # no kernel/fs support
		try:
			acls = acl_get(path, effective=False)
			if acl_is_mode(acls): raise OSError # just a mode reflection
		except OSError: acls = None # no kernel/fs support
		if not stat.S_ISLNK(fstat.st_mode):
			if acls:
				mode = stat.S_IMODE(acl_get_mode(acls))
				meta['acls'] = acls
			else: mode = stat.S_IMODE(fstat.st_mode)
			mode |= stat.S_IFMT(fstat.st_mode)
			meta['mode'] = oct(mode).lstrip('0')
		return meta

	def meta_dump(self, meta):
		uid, gid, mode, caps, acls =\
			(meta.get(k, '') for k in ['uid', 'gid', 'mode', 'caps', 'acls'])
		dump = ':'.join(['uid', 'gid', 'mode'])
		if caps or acls:
			dump += '/' + caps.replace(' ', ';')
			if acls: meta += '/' + ','.join(acls)
		return dump

	def meta_load(self, dump):
		caps = acls = None
		try:
			dump, caps = dump.split('/', 1)
			caps, acls = caps.split('/', 1)
		except ValueError: pass
		uid, gid, mode = dump.split(':')
		meta = dict( uid=uid, gid=gid,
			mode=mode, caps=caps, acls=acls ).viewitems()
		for k,v in meta.items():
			if not v: del meta[k]
		return meta


	def run(self):
		path = self.pick_path()
		if not path:
			self.log.warn('No (or non-existing) path to backup specified, exiting')
			return
		os.chdir(path)
		path_queue = self.build_queue(path)
		return self.backup_queue(path_queue)


	@defer.inlineCallbacks
	def backup_queue(self, path_queue):
		nodes = defaultdict(dict)

		with open(path_queue) as queue:
			for line in queue:
				path, obj = queue.split(None, 1)
				path_dir, name = dirname(path), basename(path)
				cap, obj = None, self.meta_load(meta)

				if not stat.S_ISDIR(int(obj.get('mode', '0'), 8)):
					# File(-like) node
					if 'mode' in obj:
						contents, data = os.stat(path), open(path)
						contents = list('{}:{}'.format( k,
							getattr(contents, k) ) for k in ['st_mtime', 'st_size'])
					else: # symlink
						data = os.readlink(path)
						contents = [data]
					cap = yield defer.maybeDeferred(self.duplicate_check(obj, contents))
					obj['cap'] = cap or (yield self.update_file(data))
					nodes[path_dir][name] = obj

				else:
					# Directory node
					contents = nodes.pop(path, dict())
					cap = yield defer.maybeDeferred(self.duplicate_check(
						obj, map(op.itemgetter('cap'), contents.viewvalues()) ))
					obj['cap'] = cap or (yield self.update_dir(obj, contents))
					nodes[path_dir][name] = obj

		yield self.update_dir(None, nodes.pop(''))

	def duplicate_check(self, obj, extras=None):
		obj_hash = meta_dump(obj)
		if extras: obj_hash += '\0' + '\0'.join(sorted(extras))
		# Not checking if the actual node is healthy - should be done separately
		return self.dentry_cache.get(key)

	def update_file(self, data):
		return self.http.request('put', self.conf.http.url, data=data)

	def update_dir(self, obj, nodes):
		contents = dict()
		for name, node in nodes.viewitems():
			node = node.copy()
			cap = node.pop('cap')
			contents[name] = (
				'dirnode' if stat.S_ISDIR(int(obj.get('mode', '0'), 8)) else 'filenode',
				dict(ro_uri=cap, metadata=node) )
		return self.http.request( 'post',
			self.conf.http.url + '?t=mkdir-immutable',
			encode='json', data=contents )


	def build_queue(self, path):
		dst = self.conf.queue
		with NamedTemporaryFile(
				dir=dirname(dst), prefix=basename(dst) + '.' ) as tmp:
			for path, meta in build_queue(path):
				tmp.write('{} {}\n'.format(path, self.meta_dump(meta)))
			tmp.flush()
			with open(dst, 'w') as queue:
				if Popen(['tac', tmp.name], stdout=queue).wait():
					raise RuntimeError('Failed to run "tac" binary (coreutils).')
		return dst

	def queue_generator(self, path):

		def _error_handler(err): raise err

		def _check_filter(path, filters=self.conf.filter):
			accept, path = True, '/' + path
			for x, pat in filters:
				assert x in '+-', 'Only +/- pattern actions are allowed.'
				if pat.search(path):
					accept = (x == '+')
					break
			return accept

		for path, dirs, files in os.walk('.', topdown=True, onerror=_error_handler):
			p = path.lstrip('./')
			yield (p, self.get_meta(p))

			for i, name in enumerate(dirs):
				path = join(p, name)
				# Filtered-out dirs won't be descended into
				if not _check_filter(path + '/'): del dirs[i]
				elif os.path.islink(path): files.append(name)

			for name in files:
				path = join(p, name)
				if not _check_filter(path): continue
				yield (path, self.get_meta(path))


def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='LAFS backup tool.')
	parser.add_argument('-c', '--config',
		action='append', metavar='path', default=list(),
		help='Configuration files to process.'
			' Can be specified more than once.'
			' Values from the latter ones override values in the former.'
			' Available CLI options override the values in any config.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	optz = parser.parse_args()

	## Read configuration files
	from twisted.python import log as twisted_log
	cfg = lya.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	## CLI overrides
	if optz.dry_run: cfg.debug.dry_run = optz.dry_run

	## Logging
	lya.configure_logging( cfg.logging,
		logging.DEBUG if optz.debug else logging.WARNING )
	twisted_log.PythonLoggingObserver().start()

	log.debug('Starting...')
	LAFSBackup(cfg).run().addBoth(lambda ignored: [reactor.stop(), ignored][1])
	reactor.start()
	log.debug('Finished')

if __name__ == '__main__': main()

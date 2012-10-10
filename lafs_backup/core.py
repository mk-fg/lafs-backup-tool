#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from glob import glob
from os.path import join, exists, isdir, dirname, basename, abspath
from collections import defaultdict
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
import os, sys, io, stat, re, types, anydbm, logging

from twisted.internet import reactor, defer
from fgc.strcaps import get_file as strcaps_get
from fgc.acl import get as acl_get,\
	is_mode as acl_is_mode, get_mode as acl_get_mode
import lya, lzma

is_str = lambda obj,s=types.StringTypes: isinstance(obj, s)

try: from lafs_backup import http
except ImportError:
	# Make sure it works from a checkout
	if isdir(join(dirname(__file__), 'lafs_backup'))\
			and exists(join(dirname(__file__), 'setup.py')):
		sys.path.insert(0, dirname(__file__))
		from lafs_backup import http



class FileCompressor(io.FileIO):

	def __init__(self, path):
		super(FileCompressor, self).__init__(path)
		self.ctx = lzma.LZMACompressor()
		self.buff = self.ctx.compress('') # header

	def read(self, n=-1):
		if not self.ctx: return self.buff
		buff, self.buff = self.buff, ''
		while n < 0 or len(buff) < n:
			src = super(FileCompressor, self).read(n)
			if src: buff += self.ctx.compress(src)
			else:
				buff += self.ctx.flush(lzma.LZMA_FINISH)
				self.ctx = None
			if not self.ctx: break
		if n > 0 and len(buff) > n: buff, self.buff = buff[:n], buff[n:]
		return buff

	def readall(): raise NotImplementedError()
	def readinto(b): raise NotImplementedError()


class LAFSBackup(object):

	conf_required = 'source.path', 'source.queue', 'source.entry_cache'

	def __init__(self, conf):
		self.conf = conf
		assert all(op.attrgetter(k)(self.conf) for k in self.conf_required),\
			'Missing some required configuration'\
				' parameters, one of: {}'.format(', '.join(self.conf_required))

		self.log = logging.getLogger('misc')
		conf.filter = list(
			( ('-', re.compile(pat))
				if is_str(pat) else (pat[0], re.compile(pat[1])) )
			for pat in (conf.filter or list()) )
		self.entry_cache = anydbm.open(conf.source.entry_cache, 'c')
		self.http = http.HTTPClient(**conf.http)


	def pick_path(self):
		paths = glob(self.conf.source.path)
		if not paths: return None
		if self.conf.source.pick_policy != 'alphasort_last':
			raise NotImplementedError( 'source.pick_policy'
				' {!r} is not implemented.'.format(self.conf.source.pick_policy) )
		return sorted(paths, reverse=True)[0]


	def meta_get(self, path):
		fstat = os.lstat(path)
		meta = dict(uid=bytes(fstat.st_uid), gid=bytes(fstat.st_gid))
		try: caps = strcaps_get(path)
		except OSError: caps = None # no kernel/fs support
		if caps: meta['caps'] = caps
		try:
			acls = acl_get(path, effective=False)
			if acl_is_mode(acls): raise OSError # just a mode reflection
		except OSError: acls = None # no kernel/fs support
		if not stat.S_ISLNK(fstat.st_mode):
			mode = fstat.st_mode
			if acls:
				meta['acls'] = acls
				mode ^= stat.S_IMODE(mode)
				mode |= stat.S_IMODE(acl_get_mode(acls))
			meta['mode'] = oct(mode).lstrip('0')
		return meta

	def meta_dump(self, meta):
		uid, gid, mode, caps, acls =\
			(meta.get(k, '') for k in ['uid', 'gid', 'mode', 'caps', 'acls'])
		dump = ':'.join([uid, gid, mode])
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
			mode=mode, caps=caps, acls=acls )
		for k,v in meta.items():
			if not v: del meta[k]
		return meta


	def run(self):
		path_queue = abspath(self.conf.source.queue)
		path = self.pick_path()
		self.log.debug('Using source path: {}'.format(path))
		if not path:
			self.log.warn('No (or non-existing) path to backup specified, exiting')
			return
		os.chdir(path)
		if not self.conf.debug.reuse_queue:
			self.build_queue(path, path_queue)
		if not self.conf.debug.queue_only:
			return self.backup_queue(basename(path), path_queue)


	@defer.inlineCallbacks
	def backup_queue(self, backup_name, path_queue):
		nodes = defaultdict(dict)

		class duplicate_check(object):
			# Not checking if the actual node is healthy - should be done separately
			def __init__( self, obj, extras=None,
					_ec=self.entry_cache, _md=self.meta_dump, _log=self.log ):
				obj_hash = _md(obj)
				if extras: obj_hash += '\0' + '\0'.join(extras)
				self.key, self.ec = obj_hash, _ec
				# _log.noise('Deduplication key: {!r}'.format(self.key))
			def check(self): return self.ec.get(dc.key)
			def set(self, cap): self.ec[dc.key] = cap

		with open(path_queue) as queue:
			for line in queue:
				line = line.strip()
				self.log.noise('Processing entry: {}'.format(line))

				try:
					path, obj = line.split(None, 1)
				except ValueError: # root dir
					path, obj = '', line
					path_dir, name = '', backup_name
				else:
					path_dir, name = dirname(path), basename(path)
				cap, obj = None, self.meta_load(obj)

				if not stat.S_ISDIR(int(obj.get('mode', '0'), 8)):
					# File(-like) node
					if 'mode' in obj:
						fstat = os.stat(path)
						if fstat.st_size < self.conf.destination.xz_min_size:
							obj['compress'], data = 'xz', FileCompressor(path)
						else: data = open(path)
						fstat = list('{}:{}'.format( k,
							int(getattr(fstat, k)) ) for k in ['st_mtime', 'st_size'])
					else: # symlink
						data = os.readlink(path)
						fstat = ['symlink:' + data]
					dc = duplicate_check(obj, [path] + fstat)
					cap = dc.check()\
						if not self.conf.debug.disable_deduplication else None
					if not cap:
						cap = yield self.update_file(data)
						dc.set(cap)
					else:
						self.log.noise('Skipping path as duplicate: {}'.format(path))
					obj['cap'], nodes[path_dir][name] = cap, obj

				else:
					# Directory node
					contents = nodes.pop(path, dict())
					dc = duplicate_check( obj,
						map(op.itemgetter('cap'), contents.viewvalues()) )
					cap = dc.check()\
						if not self.conf.debug.disable_deduplication else None
					if not cap:
						cap = yield self.update_dir(contents)
						dc.set(cap)
					obj['cap'], nodes[path_dir][name] = cap, obj

		root = nodes.pop('')[backup_name]
		self.log.debug('Root: {}'.format(root))
		defer.returnValue(root['cap'])

	def update_file(self, data):
		return self.http.request(self.conf.destination.url, 'put', data=data)

	def update_dir(self, nodes):
		contents = dict()
		for name, node in nodes.viewitems():
			node = node.copy()
			cap = node.pop('cap')
			contents[name] = (
				'dirnode' if stat.S_ISDIR(int(node.get('mode', '0'), 8)) else 'filenode',
				dict(ro_uri=cap, metadata=node) )
		return self.http.request( self.conf.destination.url
			+ '?t=mkdir-immutable', 'post', encode='json', data=contents )


	def build_queue(self, path, dst):
		with NamedTemporaryFile(
				dir=dirname(dst), prefix=basename(dst) + '.' ) as tmp:
			for path, meta in self.queue_generator(path):
				tmp.write('{} {}\n'.format(path, self.meta_dump(meta)))
			tmp.flush()
			with open(dst, 'w') as queue:
				if Popen(['tac', tmp.name], stdout=queue).wait():
					raise RuntimeError('Failed to run "tac" binary (coreutils).')

	def queue_generator(self, path):

		def _error_handler(err): raise err

		def _check_filter(path, filters=self.conf.filter):
			accept, path = True, '/' + path
			for x, pat in filters:
				assert x in '+-', 'Only +/- pattern actions are allowed.'
				if pat.search(path):
					self.log.noise('Path matched filter ({}, {}): {!r}'.format(x, pat.pattern, path))
					accept = (x == '+')
					break
			return accept

		for path, dirs, files in os.walk('.', topdown=True, onerror=_error_handler):
			p = path.lstrip('./')
			yield (p, self.meta_get(p or '.'))

			for i, name in list(enumerate(dirs)):
				path = join(p, name)
				# Filtered-out dirs won't be descended into
				if not _check_filter(path + '/'): del dirs[i]
				elif os.path.islink(path): files.append(name)

			for name in files:
				path = join(p, name)
				if not _check_filter(path): continue
				mode = os.lstat(path).st_mode
				if not stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
					self.log.info('Skipping special path: {} (mode: {})'.format(path, oct(mode)))
					continue
				yield (path, self.meta_get(path))


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

	parser.add_argument('--queue-only', action='store_true',
		help='Only generate upload queue file and stop there.')
	parser.add_argument('--reuse-queue', nargs='?', metavar='PATH',
		help='Do not generate upload queue file, use'
			' existing one (path can be specified as an argument) as-is.')
	parser.add_argument('--disable-deduplication', action='store_true',
		help='Make no effort to de-duplicate data (should still work on tahoe-level for files).')

	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	parser.add_argument('--noise',
		action='store_true', help='Even more verbose mode than --debug.')
	optz = parser.parse_args()

	## Read configuration files
	from twisted.python import log as twisted_log
	cfg = lya.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	## CLI overrides
	if optz.queue_only: cfg.debug.queue_only = optz.queue_only
	if optz.disable_deduplication:
		cfg.debug.disable_deduplication = optz.disable_deduplication
	if optz.reuse_queue:
		if optz.reuse_queue is not True:
			cfg.source.queue = optz.reuse_queue
		cfg.debug.reuse_queue = optz.reuse_queue

	## Logging
	noise = logging.NOISE = logging.DEBUG - 1
	logging.addLevelName(noise, 'NOISE')
	def noise(self, msg, noise=noise):
		if self.isEnabledFor(noise): self._log(noise, msg, ())
	logging.Logger.noise = noise

	if optz.noise: lvl = logging.NOISE
	elif optz.debug: lvl = logging.DEBUG
	else: lvl = logging.WARNING
	lya.configure_logging(cfg.logging, lvl)

	twisted_log.PythonLoggingObserver().start()
	log = logging.getLogger(__name__)

	## Start
	log.debug('Starting...')
	reactor.callLater( 0,
		lambda: defer.maybeDeferred(LAFSBackup(cfg).run)\
			.addBoth(lambda ignored: [reactor.stop(), ignored][1]) )
	reactor.run()
	log.debug('Finished')

if __name__ == '__main__': main()

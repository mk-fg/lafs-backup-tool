#!/usr/bin/env python
#-*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from glob import glob
from os.path import join, exists, isdir, dirname, basename, abspath
from datetime import datetime
from collections import defaultdict
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE
from contextlib import contextmanager
from time import time
import os, sys, io, fcntl, stat, re, types, logging
import anydbm, whichdb

from twisted.internet import reactor, defer
import lya

is_str = lambda obj,s=types.StringTypes: isinstance(obj, s)

try: import lzma
except ImportError: lzma = None

try: import anyjson as json
except ImportError:
	try: import simplejson as json
	except ImportError: import json

try: from lafs_backup import http, meta
except ImportError:
	# Make sure it works from a checkout
	if isdir(join(dirname(__file__), 'lafs_backup'))\
			and exists(join(dirname(__file__), 'setup.py')):
		sys.path.insert(0, dirname(__file__))
		from lafs_backup import http, meta



_re_type = type(re.compile(''))

def check_filters(path, filters, default=True, log=None):
	accept, path = default, '/' + path
	for rule in filters:
		try: x, pat = rule
		except (TypeError, ValueError): x, pat = '-', rule
		assert x in '+-', 'Only +/- pattern actions are allowed.'
		if not isinstance(pat, _re_type): pat = re.compile(pat)
		if pat.search(path):
			# if log: log.noise('Path matched filter ({}, {}): {!r}'.format(x, pat.pattern, path))
			accept = (x == '+')
			break
	return accept


class FileEncoder(io.FileIO):

	@classmethod
	def choose(cls, path, conf):
		if conf.xz.enabled\
				and os.stat(path).st_size > conf.xz.min_size\
				and check_filters(path, conf.xz.path_filter):
			return 'xz', cls(path, **(conf.xz.options or dict()))
		return None, open(path)

	size = size_enc = 0
	ratio = property(lambda s: (s.size_enc / float(s.size)) if s.size else 1)

	def __init__(self, path, **xz_kwz):
		super(FileEncoder, self).__init__(path)
		if not lzma: raise ImportError('Missing lzma module')
		self.ctx = lzma.LZMACompressor(**xz_kwz)
		self.buff = self.ctx.compress('') # header

	def read(self, n=-1):
		if not self.ctx: return self.buff
		buff, self.buff = self.buff, ''
		while n < 0 or len(buff) < n:
			src = super(FileEncoder, self).read(n)
			self.size += len(src)
			if src: buff += self.ctx.compress(src)
			else:
				buff += self.ctx.flush(lzma.LZMA_FINISH)
				self.ctx = None
			if not self.ctx: break
		if n > 0 and len(buff) > n: buff, self.buff = buff[:n], buff[n:]
		self.size_enc += len(buff)
		return buff

	def readall(): raise NotImplementedError()
	def readinto(b): raise NotImplementedError()


@defer.inlineCallbacks
def stopwatch_wrapper(func, *argz, **kwz):
	'Simple wrapper to naively time calls'
	ts = time()
	res = yield defer.maybeDeferred(func, *argz, **kwz)
	defer.returnValue((time() - ts, res))



class LAFSOperation(object):

	conf_required = None

	def __init__(self, conf):
		self.conf = conf
		if self.conf_required:
			assert all(op.attrgetter(k)(self.conf) for k in self.conf_required),\
				'Missing some required configuration'\
					' parameters, one of: {}'.format(', '.join(self.conf_required))
		self.log = logging.getLogger(self.__class__.__name__)



class LAFSBackup(LAFSOperation):

	conf_required = 'source.path', 'source.queue', 'source.entry_cache.path'

	def __init__(self, conf):
		super(LAFSBackup, self).__init__(conf)

		_compile_filters = lambda filters: list(
			( ('-', re.compile(pat))
				if is_str(pat) else (pat[0], re.compile(pat[1])) )
			for pat in (filters or list()) )
		conf.filter = _compile_filters(conf.filter)
		conf.destination.encoding.xz.path_filter =\
			_compile_filters(conf.destination.encoding.xz.path_filter)

		self.http = http.HTTPClient(**conf.http)
		self.meta = meta.XMetaHandler()

		self.entry_cache = anydbm.open(conf.source.entry_cache.path, 'c')


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
		try: caps = self.meta.caps.get_file(path)
		except OSError: caps = None # no kernel/fs support
		if caps: meta['caps'] = caps
		try:
			acls = self.meta.acl.get(path, effective=False)
			if self.meta.acl.is_mode(acls): raise OSError # just a mode reflection
		except OSError: acls = None # no kernel/fs support
		if not stat.S_ISLNK(fstat.st_mode):
			mode = fstat.st_mode
			if acls:
				meta['acls'] = acls
				mode ^= stat.S_IMODE(mode)
				mode |= stat.S_IMODE(self.meta.acl.get_mode(acls))
			meta['mode'] = oct(mode).lstrip('0')
		return meta

	def meta_dump(self, meta):
		uid, gid, mode, caps, acls =\
			(meta.get(k, '') for k in ['uid', 'gid', 'mode', 'caps', 'acls'])
		dump = ':'.join([uid, gid, mode])
		if caps or acls:
			dump += '/' + caps.replace(' ', ';')
			if acls: dump += '/' + ','.join(acls)
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


	@defer.inlineCallbacks
	def run(self):
		path_queue = abspath(self.conf.source.queue)
		path = self.pick_path()
		self.log.debug('Using source path: {}'.format(path))
		if not path:
			self.log.warn('No (or non-existing) path to backup specified, exiting')
			defer.returnValue(None)

		path_origin, root_cap = os.getcwd(), None
		os.chdir(path)

		if not self.conf.debug.reuse_queue:
			self.log.debug('Building queue file: {}'.format(path_queue))
			self.build_queue(path, path_queue)

		if not self.conf.debug.queue_only:
			self.log.debug('Uploading stuff from queue file: {}'.format(path_queue))
			root_cap = (yield self.backup_queue(basename(path), path_queue))\

		os.chdir(path_origin)

		if root_cap:
			if self.conf.destination.result.print_to_stdout: print(root_cap)
			if self.conf.destination.result.append_to_file:
				with open(self.conf.destination.result.append_to_file, 'a') as dst:
					fcntl.lockf(dst, fcntl.LOCK_EX)
					dst.write('{} {} {}\n'.format(datetime.now().isoformat(), path, root_cap))
			if self.conf.destination.result.append_to_lafs_dir:
				yield self.http.request(
					'{}/{}/{}?t=uri'.format( self.conf.destination.url.rstrip('/'),
						self.conf.destination.result.append_to_lafs_dir.strip('/'),
						basename(path) ), 'put', data=root_cap )

		defer.returnValue(root_cap)


	@defer.inlineCallbacks
	def backup_queue(self, backup_name, path_queue):
		nodes = defaultdict(dict)

		entry_cache_gen = json.loads(self.entry_cache.get('generation', '0')) + 1
		self.log.debug('Backup generation number: {}'.format(entry_cache_gen))
		self.entry_cache['generation'] = json.dumps(entry_cache_gen)

		class duplicate_check(object):

			# Not checking if the actual node is healthy - should be done separately
			def __init__( self, obj, extras=None,
					_ec=self.entry_cache, _md=self.meta_dump, _log=self.log ):
				self.ec, self.gen = _ec, json.loads(_ec['generation'])
				self.key = _md(obj)
				if extras: self.key += '\0' + '\0'.join(extras)
				# _log.noise('Deduplication key dump: {!r}'.format(self.key))

			def use(self):
				try: cap = self.ec[dc.key]
				except KeyError: return None
				gen, cap = json.loads(cap)
				return self.set(cap)

			def set(self, cap):
				self.ec[dc.key] = json.dumps((self.gen, cap))
				return cap

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
						enc, contents = FileEncoder.choose(
							path, self.conf.destination.encoding )
						if enc: obj['enc'] = enc
						meta = os.stat(path)
						meta = list('{}:{}'.format( k,
							int(getattr(meta, k)) ) for k in ['st_mtime', 'st_size'])
					else: # symlink
						enc, contents = None, os.readlink(path)
						meta = ['symlink:' + contents]
					dc = duplicate_check(obj, [path] + meta)
					cap = dc.use()\
						if not self.conf.debug.disable_deduplication else None
					if not cap:
						td, cap = yield stopwatch_wrapper(self.update_file, contents)
						dc.set(cap)
						self.log.noise(
							'Uploaded file (time: {:.1f}s, enc: {}, size_ratio: {:.2f}): /{}'\
							.format(td, enc, contents.ratio if enc else 1, path) )
					else:
						self.log.noise('Skipping path as duplicate: {}'.format(path))
					obj['cap'], nodes[path_dir][name] = cap, obj

				else:
					# Directory node
					contents = nodes.pop(path, dict())
					dc = duplicate_check( obj,
						map(op.itemgetter('cap'), contents.viewvalues()) )
					cap = dc.use()\
						if not self.conf.debug.disable_deduplication else None
					if not cap:
						td, cap = yield stopwatch_wrapper(self.update_dir, contents)
						dc.set(cap)
						self.log.noise('Created dirnode (time: {:.1f}s): /{}'.format(td, path))
					obj['cap'], nodes[path_dir][name] = cap, obj

		root = nodes.pop('')[backup_name]
		self.entry_cache['root:' + root['cap']] = json.dumps((
			json.loads(self.entry_cache['generation']), backup_name ))
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

		_check_filters = ft.partial(
			check_filters, filters=self.conf.filter, log=self.log )

		for path, dirs, files in os.walk('.', topdown=True, onerror=_error_handler):
			p = path.lstrip('./')
			yield (p, self.meta_get(p or '.'))

			i_off = 0
			for i, name in list(enumerate(dirs)):
				path = join(p, name)
				# Filtered-out dirs won't be descended into
				if not _check_filters(path + '/'):
					del dirs[i - i_off]
					i_off += 1 # original list just became shorter
				elif os.path.islink(path): files.append(name)

			for name in files:
				path = join(p, name)
				if not _check_filters(path): continue
				mode = os.lstat(path).st_mode
				if not stat.S_ISREG(mode) and not stat.S_ISLNK(mode):
					self.log.info('Skipping special path: {} (mode: {})'.format(path, oct(mode)))
					continue
				yield (path, self.meta_get(path))



class LAFSCleanup(LAFSOperation):

	conf_required = 'source.entry_cache.path',

	def __init__(self, conf, caps, with_history=False):
		super(LAFSCleanup, self).__init__(conf)
		self.caps, self.with_history = caps, with_history

		self.delete_from_lafs_dir = self.delete_from_file = None
		if conf.destination.result.append_to_lafs_dir:
			client = http.HTTPClient(**conf.http)
			class NotFoundError(Exception): pass
			@defer.inlineCallbacks
			def delete_from_lafs_dir(name):
				try:
					defer.returnValue((yield client.request(
						'{}/{}/{}'.format( conf.destination.url.rstrip('/'),
							conf.destination.result.append_to_lafs_dir.strip('/'), name ),
						'delete', raise_for={404: NotFoundError, 410: NotFoundError} )))
				except NotFoundError: pass
			self.delete_from_lafs_dir = delete_from_lafs_dir
		if conf.destination.result.append_to_file:
			self.delete_from_file = conf.destination.result.append_to_file

		self.entry_cache = anydbm.open(conf.source.entry_cache.path, 'c')
		self.entry_cache_t = whichdb.whichdb(conf.source.entry_cache.path)
		self.delete_batch = conf.source.entry_cache.delete_batch

	def iter_entry_cache(self):
		# A can of hacks to work with dbm salad
		if self.entry_cache_t in ['bsddb185', 'dbhash']:
			k_prev, (k, v) = None, self.entry_cache.first()
			while k != k_prev:
				yield k
				try: k_prev, (k, v) = k, self.entry_cache.next()
				except KeyError: break
		elif self.entry_cache_t in ['dbm', 'gdbm']:
			k, n = self.entry_cache.firstkey(), self.entry_cache.nextkey
			while k is not None:
				yield k
				k = n(k)
		elif self.entry_cache_t == 'dumbdbm':
			for k in self.entry_cache.keys(): yield k
		else:
			raise TypeError('Unrecognized dbm type: {!r}'.format(self.entry_cache_t))

	@defer.inlineCallbacks
	def run(self):
		gen_max, caps_found = 0, dict()

		for cap in self.caps:
			cap_key = 'root:' + cap
			try: gen, name = json.loads(self.entry_cache[cap_key])
			except KeyError: continue
			gen_max = max(gen, gen_max)
			caps_found[cap_key] = gen, name, cap

		if gen_max:
			cap_gen_chk = set(it.imap(op.itemgetter(0), caps_found.viewvalues()))
			self.log.debug( 'Scanning entry_cache for generations'
				' (max: {}): {}'.format(gen_max, ', '.join(it.imap(bytes, cap_gen_chk))) )

			cleanup_keys = set()
			def key_cleanup():
				for k in cleanup_keys: del self.entry_cache[k]
				cleanup_keys.clear()

			ec_iter = self.iter_entry_cache()
			while True:
				try: k = next(ec_iter)
				except StopIteration: break

				if k == 'generation': pass
				elif k.startswith('root:'):
					gen = json.loads(self.entry_cache[k])
					if self.with_history and gen < gen_max and gen not in cap_gen_chk:
						cleanup_keys.add(k)
				else:
					gen, cap = json.loads(self.entry_cache[k])
					if gen >= gen_max:
						if self.with_history or gen in cap_gen_chk: cleanup_keys.add(k)

				if self.delete_batch and len(cleanup_keys) > self.delete_batch:
					key_cleanup()
					ec_iter = self.iter_entry_cache() # restart iteration

			key_cleanup()

		if caps_found:
			self.log.debug('Removing root caps from entry_cache')
			for cap_key, (gen, name, cap) in caps_found.viewitems():
				if self.delete_from_lafs_dir: yield self.delete_from_lafs_dir(name)
				if self.delete_from_file:
					with open(self.delete_from_file, 'a+') as dst:
						fcntl.lockf(dst, fcntl.LOCK_EX)
						data = ''.join(line for line in dst if line.split()[-1] != cap)
						dst.seek(0)
						dst.truncate()
						dst.write(data)
				del self.entry_cache[cap_key]

		if gen_max or caps_found:
			try: self.entry_cache.sync()
			except AttributeError: pass
			try: self.entry_cache.reorganize() # gdbm
			except AttributeError: pass



def main(argv=None):
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
	parser.add_argument('--noise',
		action='store_true', help='Even more verbose mode than --debug.')

	cmds = parser.add_subparsers(
		title='Supported operations (have their own suboptions as well)')

	@contextmanager
	def subcommand(name, **kwz):
		cmd = cmds.add_parser(name, **kwz)
		cmd.set_defaults(call=name)
		yield cmd

	with subcommand('backup', help='Backup data to LAFS.') as cmd:
		cmd.add_argument('--queue-only', nargs='?', metavar='path',
			help='Only generate upload queue file (path can'
				' be specified as an optional argument) and stop there.')
		cmd.add_argument('--reuse-queue', nargs='?', metavar='path',
			help='Do not generate upload queue file, use'
				' existing one (path can be specified as an argument) as-is.')
		cmd.add_argument('--disable-deduplication', action='store_true',
			help='Make no effort to de-duplicate data (should still work on tahoe-level for files).')

	with subcommand('cleanup',
			help='Remove the backup from LAFS and local caches.') as cmd:
		cmd.add_argument('root_cap',
			nargs='*', metavar='LAFS-URI', default=list(),
			help='LAFS URI(s) of the backup(s) to remove.'
				'If not specified (or "-" is used), will be read from stdin.')
		cmd.add_argument('--up-to', action='store_true',
			help='Make sure to remove all the previous known backups as well.')

	with subcommand('dump_config',
		help='Dump configuration to stdout and exit.') as cmd: pass

	optz = parser.parse_args(argv or sys.argv[1:])

	## Read configuration files
	from twisted.python import log as twisted_log
	cfg = lya.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

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

	## Operation-specific CLI processing
	if optz.call == 'backup':
		if optz.disable_deduplication:
			cfg.debug.disable_deduplication = optz.disable_deduplication
		if optz.queue_only:
			if optz.queue_only is not True:
				cfg.source.queue = optz.queue_only
			cfg.debug.queue_only = optz.queue_only
		elif cfg.destination.encoding.xz.enabled and not lzma:
			raise ImportError('Missing lzma module')
		if optz.reuse_queue:
			if optz.reuse_queue is not True:
				cfg.source.queue = optz.reuse_queue
			cfg.debug.reuse_queue = optz.reuse_queue

		op = LAFSBackup(cfg).run

	elif optz.call == 'cleanup':
		caps = set(optz.root_cap).difference({'-'})
		if not optz.root_cap or '-' in optz.root_cap:
			caps.update(it.ifilter(None, (line.strip() for line in sys.stdin)))
		op = LAFSCleanup(cfg, caps, optz.up_to).run

	elif optz.call == 'dump_config': op = ft.partial(cfg.dump, sys.stdout)

	else: parser.error('Unrecognized command: {}'.format(optz.call))

	## Actual work
	log.debug('Starting...')
	reactor.callLater( 0,
		lambda: defer.maybeDeferred(op)\
			.addBoth(lambda ignored: [reactor.stop(), ignored][1]) )
	reactor.run()
	log.debug('Finished')

if __name__ == '__main__': main()

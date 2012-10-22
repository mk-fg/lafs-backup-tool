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

from twisted.internet import reactor, defer
import lya

is_str = lambda obj,s=types.StringTypes: isinstance(obj, s)

try: import lzma
except ImportError: lzma = None

try: from lafs_backup import http, meta, db
except ImportError:
	# Make sure it works from a checkout
	if isdir(join(dirname(__file__), 'lafs_backup'))\
			and exists(join(dirname(__file__), 'setup.py')):
		sys.path.insert(0, dirname(__file__))
	from lafs_backup import http, meta, db


_re_type = type(re.compile(''))

def check_filters(path, filters, default=True, log=None):
	path = '/' + path
	for rule in filters:
		try: x, pat = rule
		except (TypeError, ValueError): x, pat = False, rule
		if not isinstance(pat, _re_type): pat = re.compile(pat)
		if pat.search(path):
			# if log: log.noise('Path matched filter ({}, {}): {!r}'.format(x, pat.pattern, path))
			return x
	return default


class FileEncoder(io.FileIO):

	@classmethod
	def choose(cls, path, conf):
		if conf.xz.enabled:
			min_size = check_filters( path,
				conf.xz.path_filter, default=conf.xz.min_size )
			assert isinstance(min_size, (bool, int, long, float)),\
				'Unrecognized xz path_filter result value: {}'.format(min_size)
			if min_size is True: min_size = conf.xz.min_size
			if min_size is None: min_size = False
			if min_size is not False and os.stat(path).st_size >= min_size:
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
		buff, self.buff = self.buff, ''
		while self.ctx and (n < 0 or len(buff) < n):
			src = super(FileEncoder, self).read(n)
			self.size += len(src)
			if src: buff += self.ctx.compress(src)
			else:
				buff += self.ctx.flush(lzma.LZMA_FINISH)
				self.ctx = None
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
	conf_required_init = 'source.entry_cache.path',

	def __init__(self, conf):
		self.conf = conf
		self.conf_required = list(self.conf_required or list())
		self.conf_required.extend(list(self.conf_required_init) or list())
		if self.conf_required:
			assert all(op.attrgetter(k)(self.conf) for k in self.conf_required),\
				'Missing some required configuration'\
					' parameters, one of: {}'.format(', '.join(self.conf_required))
		self.log = logging.getLogger(self.__class__.__name__)

		sql_log = logging.getLogger('lafs_backup.EntryCacheDB')\
			if conf.logging.sql_queries else None
		self.entry_cache = db.EntryCacheDB(conf.source.entry_cache.path, log=sql_log)



class LAFSBackup(LAFSOperation):

	conf_required = 'source.path', 'source.queue.path'

	def __init__(self, conf):
		super(LAFSBackup, self).__init__(conf)

		_filter_actions = {'+': True, '-': False}
		_compile_filters = lambda filters, c=lambda v: v: list(
			( (False, re.compile(pat))
				if is_str(pat) else (c(pat[0]), re.compile(pat[1])) )
			for pat in (filters or list()) )

		conf.filter = _compile_filters(conf.filter, lambda v, c=_filter_actions: c[v])
		conf.destination.encoding.xz.path_filter = _compile_filters( # also allows size value
			conf.destination.encoding.xz.path_filter, lambda v, c=_filter_actions: c.get(v, v) )

		self.http = http.HTTPClient(**conf.http)
		self.meta = meta.XMetaHandler()


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
		path_queue = abspath(self.conf.source.queue.path)
		path = self.pick_path()
		self.log.debug('Using source path: {}'.format(path))
		if not path:
			self.log.warn('No (or non-existing) path to backup specified, exiting')
			defer.returnValue(None)

		if self.conf.source.queue.check_mtime\
				and os.stat(path_queue).st_mtime > os.stat(path).st_mtime:
			self.log.debug( 'Reusing queue-file (newer'
				' mtime than source path): {}'.format(path_queue) )
			self.conf.operation.reuse_queue = True

		path_origin, root_cap = os.getcwd(), None
		os.chdir(path)

		if not self.conf.operation.reuse_queue:
			self.log.debug('Building queue file: {}'.format(path_queue))
			self.build_queue(path, path_queue)

		if not self.conf.operation.queue_only:
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
		generation = self.entry_cache.get_new_generation()
		self.log.debug('Backup generation number: {}'.format(generation))

		ts_start = time()
		c_bytes = c_objs = 0
		rate_limits = self.conf.operation.rate_limit
		rate_limits_enabled = rate_limits.interval\
			and (rate_limits.bytes or rate_limits.objects)

		def rate_limit_check(metric, val, interval=rate_limits.interval):
			rate_max = getattr(rate_limits, metric, None) or 0
			if rate_max <= 0: return
			ts_diff = float(time() - ts_start) / interval
			rate = val / ts_diff
			if rate > rate_max:
				delay = ( (val - rate_max * ts_diff) / rate_max ) * interval
				d = defer.Deferred()
				reactor.callLater(delay, d.callback, None)
				self.log.noise( 'Introducing rate-limiting delay (metric:'
					' {}, rate: {:.1f}, rate_max: {:.1f}): {:.1f}s'.format(metric, rate, rate_max, delay) )
				return d

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
						ts, size = op.attrgetter('st_mtime', 'st_size')(os.stat(path))
						meta = ['st_mtime:{:.3f}'.format(ts), 'st_size:{}'.format(size)]
					else: # symlink
						enc, contents = None, os.readlink(path)
						meta, size = ['symlink:' + contents], len(contents)
					dc = self.entry_cache.duplicate_check(
						self.meta_dump(obj), generation, [path] + meta )
					cap = dc.use()\
						if not self.conf.operation.disable_deduplication else None
					if not cap:
						ts, cap = yield stopwatch_wrapper(self.update_file, contents)
						dc.set(cap)
						self.log.noise(
							'Uploaded file (time: {:.1f}s, size: {}, enc: {}): /{}'\
							.format(ts, size, '{}[{:.2f}]'.format(
								enc, contents.ratio ) if enc else 'no', path) )
						c_bytes += size
						c_objs += 1
					else:
						self.log.noise('Skipping path as duplicate: {}'.format(path))
					obj['cap'], nodes[path_dir][name] = cap, obj

				else:
					# Directory node
					contents = nodes.pop(path, dict())
					dc = self.entry_cache.duplicate_check(
						self.meta_dump(obj), generation,
						map(op.itemgetter('cap'), contents.viewvalues()) )
					cap = dc.use()\
						if not self.conf.operation.disable_deduplication else None
					if not cap:
						ts, cap = yield stopwatch_wrapper(self.update_dir, contents)
						dc.set(cap)
						self.log.noise(
							'Created dirnode (time: {:.1f}s, nodes: {}): /{}'\
							.format(ts, len(contents), path) )
						c_objs += 1
					else:
						self.log.noise('Skipping path as duplicate: {}'.format(path))
					obj['cap'], nodes[path_dir][name] = cap, obj

				# Check rate-limiting and introduce delay, if necessary
				if rate_limits_enabled:
					yield rate_limit_check('bytes', c_bytes)
					yield rate_limit_check('objects', c_objs)

		root = nodes.pop('')[backup_name]
		self.entry_cache.backup_add(backup_name, root['cap'], generation)
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

	def __init__(self, conf, caps, gens, with_history=False):
		super(LAFSCleanup, self).__init__(conf)
		self.caps, self.gens, self.with_history = caps, gens, with_history

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

	@defer.inlineCallbacks
	def run(self):
		gen_max, caps_found = 0, dict()
		count_pe = count_baks = 0

		for cap in self.caps:
			try: bak = self.entry_cache.backup_get(cap=cap)
			except KeyError: continue
			gen_max = max(bak['generation'], gen_max)
			caps_found[cap] = bak

		for gen in self.gens:
			gen_max = max(gen, gen_max)
			backups = list()
			if self.with_history:
				backups.extend(self.entry_cache.backup_get_gen(gen, exact=False))
			else:
				try: backups.append(self.entry_cache.backup_get_gen(gen))
				except KeyError: pass
			for bak in backups: caps_found[bak['cap']] = bak

		if gen_max:
			cap_gen_chk = set(it.imap(
				op.itemgetter('generation'), caps_found.viewvalues() ))
			cap_gen_chk.update(self.gens)
			self.log.debug( 'Scanning entry_cache for generations'
				' (max: {}): {}'.format(gen_max, ', '.join(it.imap(bytes, cap_gen_chk))) )

			if self.with_history:
				for gen in cap_gen_chk:
					count_pe += self.entry_cache.delete_generations(gen)
			else:
				count_pe += self.entry_cache.delete_generations(gen_max, exact=False)

		if caps_found:
			self.log.debug('Removing root caps from entry_cache')
			for cap_key, bak in caps_found.viewitems():
				if self.delete_from_lafs_dir: yield self.delete_from_lafs_dir(bak['name'])
				if self.delete_from_file:
					with open(self.delete_from_file, 'a+') as dst:
						fcntl.lockf(dst, fcntl.LOCK_EX)
						data = ''.join(line for line in dst if line.split()[-1] != bak['cap'])
						dst.seek(0)
						dst.truncate()
						dst.write(data)
				self.entry_cache.backup_del(bak['cap'])
				count_baks += 1

		self.log.debug(( 'Removed: {} path entries,'
			' {} backup entries' ).format(count_pe, count_baks))



class LAFSList(LAFSOperation):

	def __init__(self, conf, list_dangling_gens=None):
		super(LAFSList, self).__init__(conf)
		self.list_dangling_gens = list_dangling_gens

	def run(self):
		gen_max = self.entry_cache.get_new_generation()

		gens = set()
		for i, bak in enumerate( self.entry_cache\
				.backup_get_gen(gen_max, exact=False) ):
			if i: print()
			print(( 'Backup: {0[name]}\n  cap: {0[cap]}\n  generation:'
				' {0[generation]}\n  timestamp: {1}' ).format(
					bak, datetime.fromtimestamp(bak['ts']).isoformat() ))
			gens.add(bak['generation'])

		if self.list_dangling_gens is not None:
			if self.list_dangling_gens: gen_max = None
			objects = it.groupby(
				sorted(
					self.entry_cache.get_generations( gen_max,
						include=self.list_dangling_gens, exclude=gens ),
					key=op.itemgetter('generation') ),
				key=op.itemgetter('generation') )
			if objects:
				i = 0
				for gen, objects in objects:
					if i: print('\n')
					print('Generation: {}'.format(gen))
					for obj in objects:
						i += 1
						print('  {}. ts: {}, metadata: {!r}'.format(i, obj['ts'], obj['metadata_dump']))




def main(argv=None, config=None):
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
		cmd.add_argument('--queue-only',
			nargs='?', metavar='path', default=False,
			help='Only generate upload queue file (path can'
				' be specified as an optional argument) and stop there.')
		cmd.add_argument('--reuse-queue',
			nargs='?', metavar='path', default=False,
			help='Do not generate upload queue file, use'
				' existing one (path can be specified as an argument) as-is.')
		cmd.add_argument('-f', '--force-queue-rebuild', action='store_true',
			help='Force upload queue file rebuild,'
				' even if one already exists and is recent enough to be reused.')
		cmd.add_argument('--disable-deduplication', action='store_true',
			help='Make no effort to de-duplicate data (should still work on tahoe-level for files).')

	with subcommand('cleanup',
			help='Remove the backup from local caches and unlink from'
					' LAFS destination mutable directory (if configured).'
				' Purpose is to make local system (and accessible from it lafs path) "forget"'
					' about specified backups, not to actually remove any backed-up data.') as cmd:
		cmd.add_argument('root_cap',
			nargs='*', metavar='LAFS-URI', default=list(),
			help='LAFS URI(s) of the backup(s) to remove.'
				'If not specified (or "-" is used), will be read from stdin.')
		cmd.add_argument('--up-to', action='store_true',
			help='Make sure to remove all the previous known backups / generations as well.')
		cmd.add_argument('-g', '--generation',
			action='append', type=int, default=list(),
			help='Also remove specified backup generations. Affected by --up-to option.'
				' If no URIs (or "-") will be specified as arguments, stdin stream wont be scanned'
				' for them and only specified (with this option) backup generations will be removed.')

	with subcommand('list', help='List known finished backups.') as cmd:
		cmd.add_argument('-g', '--generations',
			action='append', type=int, nargs='*',
			help='Also list dangling entries in cache with generation numbers'
				' not linked to any finished backup. More specific generation numbers'
				' can be specified as an arguments to only list these.')

	with subcommand('dump_config',
		help='Dump configuration to stdout and exit.') as cmd: pass

	optz = parser.parse_args(argv or sys.argv[1:])

	## Read configuration
	cfg = lya.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)
	if config: cfg.update_dict(config)

	## Logging
	from twisted.python import log as twisted_log

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
			cfg.operation.disable_deduplication = optz.disable_deduplication
		if optz.force_queue_rebuild:
			cfg.source.queue.check_mtime = False
		if optz.queue_only is not False:
			if optz.queue_only is not None:
				cfg.source.queue.path = optz.queue_only
			cfg.operation.queue_only = optz.queue_only
		elif cfg.destination.encoding.xz.enabled and not lzma:
			raise ImportError('Unable to import lzma module')
		if optz.reuse_queue is not False:
			if optz.force_queue_rebuild:
				parser.error('Options --force-queue-rebuild'
					' and --reuse-queue cannot be used together.')
			if optz.reuse_queue is not None:
				cfg.source.queue.path = optz.reuse_queue
			cfg.operation.reuse_queue = optz.reuse_queue
		op = LAFSBackup(cfg).run

	elif optz.call == 'cleanup':
		caps = set(optz.root_cap).difference({'-'})
		if (not optz.generation and not optz.root_cap) or '-' in optz.root_cap:
			caps.update(it.ifilter(None, (line.strip() for line in sys.stdin)))
		op = LAFSCleanup(cfg, caps, optz.generation, optz.up_to).run

	elif optz.call == 'list':
		if optz.generations is not None:
			optz.generations = set(it.chain.from_iterable(optz.generations))
		op = LAFSList(cfg, list_dangling_gens=optz.generations).run

	elif optz.call == 'dump_config': op = ft.partial(cfg.dump, sys.stdout)

	else: parser.error('Unrecognized command: {}'.format(optz.call))

	## Actual work
	def _stop(res):
		if reactor.running: reactor.stop()
		return res
	reactor.callWhenRunning(
		lambda: defer.maybeDeferred(op).addBoth(_stop) )
	log.debug('Starting...')
	reactor.run()
	log.debug('Finished')

if __name__ == '__main__': main()

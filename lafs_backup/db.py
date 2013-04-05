#-*- coding: utf-8 -*-

import itertools as it, operator as op, functools as ft
from collections import OrderedDict
from contextlib import contextmanager, closing
from time import time
import sqlite3


class BackupEntry(object):

	def __init__(self, query_func, key, gen, extras=None):
		self.q, self.key, self.gen = query_func, key, gen
		if extras: self.key += '\0' + '\0'.join(extras)

	def use(self):
		with self.q( 'SELECT cap'
				' FROM object_cache WHERE metadata_dump = ?'
				' LIMIT 1', (self.key,) ) as c:
			row = c.fetchone()
		if not row: return None
		return self.set(row['cap'])

	def set(self, cap):
		with self.q( 'INSERT INTO object_cache'
			' (metadata_dump, cap, generation, ts)'
			' VALUES (?, ?, ?, ?)', (self.key, cap, self.gen, time()) ): pass
		return cap


class EntryCacheDB(object):

	_db_init = '''
		CREATE TABLE IF NOT EXISTS object_cache (
			metadata_dump BLOB PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
			cap TEXT NOT NULL,
			generation INT NOT NULL,
			ts REAL NOT NULL
		);
		CREATE INDEX IF NOT EXISTS oc_meta ON object_cache (metadata_dump);
		CREATE INDEX IF NOT EXISTS oc_gen ON object_cache (generation);

		CREATE TABLE IF NOT EXISTS backups (
			name TEXT NOT NULL,
			cap TEXT NOT NULL,
			generation INT NOT NULL,
			ts REAL NOT NULL
		);
		CREATE INDEX IF NOT EXISTS backups_cap ON backups (cap);
		CREATE INDEX IF NOT EXISTS backups_gen ON backups (generation);

		CREATE TABLE IF NOT EXISTS meta (
			var TEXT PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
			val TEXT NOT NULL
		);
	'''

	_db_migrations = [
		'''ALTER TABLE backups ADD COLUMN ts_check REAL NULL;
			CREATE INDEX backups_ts_check ON backups (ts_check);''' ]

	_db = None


	def __init__(self, path, log=None):
		self._log, self._db = log, sqlite3.connect(path)
		self._db.row_factory = sqlite3.Row
		self._init_db()

	def __del__(self):
		if self._db: self._db.close()

	@contextmanager
	def _cursor(self, query, params=tuple(), **kwz):
		if self._log:
			self._log.noise('Query: {!r}, data: {!r}'.format(query, params))
		with self._db as db:
			with closing(db.execute(query, params, **kwz)) as c:
				yield c

	def _query(self, *query_argz, **query_kwz):
		with self._cursor(*query_argz, **query_kwz): pass

	def _init_db(self):
		with self._db as db: db.executescript(self._db_init)
		with self._cursor("SELECT val FROM meta WHERE var = 'schema_version' LIMIT 1") as c:
			row = c.fetchone()
			schema_ver = int(row['val']) if row else 1
		for schema_ver, query in enumerate(
			self._db_migrations[schema_ver-1:], schema_ver ): db.executescript(query)
		self._query( 'INSERT INTO meta (var, val)'
			" VALUES ('schema_version', '{}')".format(schema_ver + 1) )


	def get_new_generation(self):
		with self._cursor('SELECT generation'
				' FROM object_cache ORDER BY generation DESC LIMIT 1') as c:
			row = c.fetchone()
			gen = (row['generation'] + 1) if row else 1
		with self._cursor('SELECT generation'
				' FROM backups ORDER BY generation DESC LIMIT 1') as c:
			row = c.fetchone()
			if row: gen = max(gen, row['generation'] + 1)
		return gen

	def duplicate_check(self, obj_dump, gen, extras=None):
		return BackupEntry(self._cursor, obj_dump, gen, extras=extras)

	def delete_generations(self, gen, exact=True):
		with self._cursor( 'DELETE FROM object_cache'
				' WHERE generation {} ?'.format('=' if exact else '<='), (gen,) ) as c:
			return c.rowcount

	def get_generations(self, gen_max=None, include=set(), exclude=set()):
		'Composition: [ (gen_max [OR include]) [AND exclude] ]'
		params = list()
		if gen_max:
			params.append(gen_max)
			gen_max = 'generation <= ?'
		else: gen_max = '1' if not include else '0'
		if include:
			params.extend(include)
			include = 'OR generation IN ({})'.format(', '.join(['?']*len(include)))
		else: include = ''
		if exclude:
			params.extend(exclude)
			exclude = 'AND generation NOT IN ({})'.format(', '.join(['?']*len(exclude)))
		else: exclude = ''
		with self._cursor( 'SELECT * FROM object_cache'
				' WHERE ({} {}) {}'.format(gen_max, include, exclude), params ) as c:
			return c.fetchall()


	def backup_add(self, name, cap, gen):
		self._query(
			'INSERT INTO backups (name, cap, generation, ts)'
			' VALUES (?, ?, ?, ?)', (name, cap, gen, time()) )

	def backup_get(self, name=None, cap=None):
		fields = OrderedDict((k, v) for k,v in dict(name=name, cap=cap).viewitems() if v)
		with self._cursor( 'SELECT * FROM backups'
					' WHERE {} LIMIT 1'.format(' AND '.join('{} = ?'.format(k) for k in fields)),
				tuple(fields.values()) ) as c:
			row = c.fetchone()
			if not row: raise KeyError(fields)
			return row

	def backup_get_gen(self, gen, exact=True):
		with self._cursor( 'SELECT * FROM backups'
				' WHERE generation {} ?'.format('=' if exact else '<='), (gen,) ) as c:
			if exact:
				ret = c.fetchone()
				if not ret: raise KeyError(gen)
			else: ret = c.fetchall()
			return ret

	def backup_get_least_recently_checked(self, caps=None):
		caps_filter, params = '', list()
		if caps:
			caps_filter = 'WHERE cap IN ({})'.format(', '.join(['?']*len(caps)))
			params.extend(caps)
		with self._cursor( 'SELECT * FROM backups'
				' {} ORDER BY ts_check LIMIT 1'.format(caps_filter), params ) as c:
			row = c.fetchone()
			if not row: raise KeyError(caps)
			return row['cap']

	def backup_checked(self, cap):
		self._query('UPDATE backups SET ts_check = ? WHERE cap = ?', (time(), cap))

	def backup_del(self, cap):
		self._query('DELETE FROM backups WHERE cap = ?', (cap,))

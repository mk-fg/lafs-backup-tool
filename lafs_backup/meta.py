#-*- coding: utf-8 -*-
from __future__ import print_function

# Whole module is just a cffi rebase of https://github.com/mk-fg/fgc

import itertools as it, operator as op, functools as ft
import os, sys, re, errno, types

from cffi import FFI



class CStrACL(object):

	_lazy = None
	@classmethod
	def lazy_instance(cls):
		if not cls._lazy: cls._lazy = cls()
		return cls._lazy


	def __init__(self):
		self.ffi = FFI()
		cdef = '''
			struct __acl_ext;
			typedef struct __acl_ext *acl_t;
			typedef unsigned int acl_type_t;
			typedef unsigned int mode_t;

			static const acl_type_t ACL_TYPE_ACCESS;
			static const acl_type_t ACL_TYPE_DEFAULT;

			static const int TEXT_ABBREVIATE;
			static const int TEXT_NUMERIC_IDS;
			static const int TEXT_SOME_EFFECTIVE;
			static const int TEXT_ALL_EFFECTIVE;
			static const int TEXT_SMART_INDENT;

			acl_t acl_init(int count);
			acl_t acl_get_file(const char *path_p, acl_type_t type);
			acl_t acl_from_mode(mode_t mode);
			acl_t acl_from_text(const char *buf_p);
			char *acl_to_any_text(
				acl_t acl, const char *prefix, char separator, int options );

			int acl_calc_mask(acl_t *acl_p);
			int acl_set_file(const char *path_p, acl_type_t type, acl_t acl);
			int acl_set_fd(int fd, acl_t acl);

			int acl_free(void *obj_p);
		'''
		self.ffi.cdef(cdef)

		self.libacl = self.ffi.verify('''
			#include <sys/types.h>
			#include <sys/acl.h>
			#include <acl/libacl.h>
		''', libraries=['acl'])

		self._flag_cache = dict()
		for k, pre, alias in re.findall(r'\b((ACL_TYPE|TEXT)_([A-Z_]+))\b', cdef):
			v = getattr(self.libacl, k)
			setattr(self, k, v)
			if alias not in self._flag_cache: self._flag_cache[alias] = v
			else: self._flag_cache[alias] = None


	def _flag(self, k):
		if isinstance(k, (int, long)): return k
		elif not isinstance(k, types.StringTypes):
			return reduce(op.or_, it.imap(self._flag, k), 0)
		v = self._flag_cache[k]
		if v is not None: return v
		else: raise KeyError('Ambiguous flag name: {}'.format(k))

	def get( self, src, acl_type='ACCESS',
			text_options=['ABBREVIATE', 'ALL_EFFECTIVE'] ):
		if isinstance(src, types.StringTypes): func = self.libacl.acl_get_file
		else:
			if not isinstance(src, (int, long)): src = src.fileno()
			func = self.libacl.acl_get_fd
		acl = func(src, self._flag(acl_type))

		try:
			if acl == self.ffi.NULL:
				if self.ffi.errno == errno.ENODATA: return ''
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

			acl_str = self.libacl.acl_to_any_text(
				acl, self.ffi.NULL, '\n', self._flag(text_options) )
			if acl == self.ffi.NULL:
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))
			acl_str = self.ffi.string(acl_str)
			return acl_str

		finally:
			if acl != self.ffi.NULL and self.libacl.acl_free(acl):
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

	def _set(self, dst, acl_str, acl_type='ACCESS'):
		acl = self.libacl.acl_from_text(acl_str)\
			if acl_str is not None else self.libacl.acl_init(5)
		if acl == self.ffi.NULL:
			raise ValueError('Invalid ACL specification: {!r}'.format(acl_str))

		try:
			acl_p = self.ffi.new('acl_t *', acl)
			if self.libacl.acl_calc_mask(acl_p):
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

			acl_type = self._flag(acl_type)
			if isinstance(dst, types.StringTypes):
				err = self.libacl.acl_set_file(dst, acl_type, acl)
			else:
				if not isinstance(dst, (int, long)): dst = dst.fileno()
				err = self.libacl.acl_set_fd(dst, acl)
			if err: raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

		finally:
			if self.libacl.acl_free(acl):
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

	def set(self, dst, acl_str, acl_type='ACCESS'):
		return self._set(dst, acl_str, acl_type=acl_type)

	def unset(self, dst, acl_type='ACCESS'):
		return self._set(dst, None, acl_type=acl_type)

	def from_mode( self, mode,
			text_options=['ABBREVIATE', 'ALL_EFFECTIVE'] ):
		acl = self.libacl.acl_from_mode(mode)
		if acl == self.ffi.NULL:
			raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

		try:
			acl_str = self.libacl.acl_to_any_text(
				acl, self.ffi.NULL, '\n', self._flag(text_options) )
			return self.ffi.string(acl_str)

		finally:
			if self.libacl.acl_free(acl):
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))



_mode = lambda x: '::' in x
_eff_drop = lambda x: x.split('\t')[0]
_eff_set = lambda x: '{0}:{1}'.format(
	x.split('\t')[0].rsplit(':', 1)[0], x.rsplit('\t')[-1].rsplit(':', 1)[-1] )
_def_get = lambda x: x.startswith('d:')
_def_set = lambda x: 'd:{0}'.format(x)
_def_strip = op.itemgetter(slice(2, None))
_line_id = lambda x:\
	(x[0] if not x.startswith('d:') else x[:3])\
		if _mode(x) else x.rsplit(':', 1)[0]

_mode_bits = (
	0400, 0200, 0100, # rwx --- ---
	0040, 0020, 0010, # --- rwx ---
	0004, 0002, 0001 )# --- --- rwx


class StrACL(CStrACL):

	## High-level fs ACL manipulation API

	def get( self, dst, mode_filter=None,
			effective=True, acl_type=None ):
		'Get ACL for a given path, file or fd'
		acl, stracl = list(), super(StrACL, self)
		effective = _eff_set if effective else _eff_drop
		if mode_filter is None: mode_filter = iter
		else:
			mode_filter = ft.partial(
				it.ifilter if mode_filter else it.ifilterfalse, _mode )
		if not acl_type or acl_type & self.ACL_TYPE_ACCESS:
			acl = it.chain(acl, it.imap(
				effective, mode_filter(stracl.get(dst).splitlines())))
		if (not acl_type or acl_type & self.ACL_TYPE_DEFAULT) and \
				isinstance(dst, types.StringTypes) and os.path.isdir(dst):
			acl = it.chain(acl, it.imap(_def_set, it.imap( effective,
				mode_filter(stracl.get(dst, self.ACL_TYPE_DEFAULT).splitlines()) )))
		return list(acl)

	def get_mode(self, acl):
		'Get mode from acl, path, file or fd'
		if isinstance(acl, (int, types.StringTypes)):
			acl = self.get(acl, mode_filter=True, acl_type=self.ACL_TYPE_ACCESS)
		acl = dict((line[0], line[3:]) for line in it.ifilter(_mode, acl))
		return self.mode(''.join(acl[x] for x in 'ugo'))

	def rebase(self, dst, acl, base=None, discard_old_mode=False):
		'Rebase given ACL lines on top of ones, generated from mode'
		acl, stracl = self.canonized(acl), super(StrACL, self)

		# ACL base
		if not base and not base == 0: # get current base, if unspecified
			base = filter(_mode, self.get(
				dst, mode_filter=True, acl_type=self.ACL_TYPE_ACCESS ))
		else: # convert given mode to a canonical base-ACL
			if not isinstance(base, (int, long)): base = self.mode(base)
			base = self.from_mode(int(base))

		# Access ACL
		ext = it.ifilterfalse(_def_get, acl)
		stracl.set( dst, '\n'.join( self.update(ext, base)
				if discard_old_mode else self.update(base, ext) ),
			self.ACL_TYPE_ACCESS )

		# Default ACL
		if isinstance(dst, types.StringTypes) and os.path.isdir(dst):
			ext = it.imap(_def_strip, it.ifilter(_def_get, acl))
			stracl.set( dst, '\n'.join( self.update(ext, base)
					if discard_old_mode else self.update(base, ext) ),
				self.ACL_TYPE_DEFAULT )

	def set(self, dst, acl):
		'''Just set ACL to a given value,
		 which must contain all mode-lines as well'''
		acl, stracl = self.canonized(acl), super(StrACL, self)
		stracl.set(dst, '\n'.join(it.ifilterfalse(_def_get, acl)))
		if isinstance(dst, types.StringTypes) and os.path.isdir(dst):
			stracl.set( dst,
				'\n'.join(it.imap(_def_strip, it.ifilter(_def_get, acl))),
				self.ACL_TYPE_DEFAULT )

	def fix_mask(self, dst):
		'''Fix mask-crippled acls after chmod
			by updating mask from ACL entries.'''
		return self.set(dst, self.get(dst, effective=False))

	## ACL list manipulation methods

	def from_mode(self, mode):
		return self.canonized(super(StrACL, self).from_mode(mode))

	def mode(self, strspec, base=0):
		for n in xrange(len(_mode_bits)):
			if strspec[n] != '-': base |= _mode_bits[n]
		return base

	def update(self, base, ext):
		'Rebase one ACL on top of the other'
		res = dict((_line_id(line), line) for line in base)
		res.update((_line_id(line), line) for line in ext)
		return res.values()

	def update_from_default(self, acl):
		'''Update non-default acl lines from default lines,
				possibly overriding acls for the same target.
			Useful to fix mask-crippled acls after chmod.'''
		if not self.has_defaults(acl): return acl
		return self.update(acl, (line[2:] for line in acl if line.startswith('d:')))

	def canonized(self, acl):
		'Break down ACL string into a list-form'
		if isinstance(acl, types.StringTypes):
			acl = filter(
				lambda x: x and x[0] != '#',
				acl.replace('\n', ',').split(',') )
		return acl

	def has_defaults(self, acl):
		'Check if ACL has "default" entries'
		for line in acl:
			if _def_get(line): return True
		else: return False

	def is_mode(self, acl):
		'Check if ACL is just a reflection of mode bitmask'
		for line in acl:
			if not _mode(line) or _def_get(line): return False
		else: return True



class CStrCaps(object):

	_lazy = None
	@classmethod
	def lazy_instance(cls):
		if not cls._lazy: cls._lazy = cls()
		return cls._lazy


	def __init__(self):
		self.ffi = FFI()
		cdef = '''
			struct _cap_struct;
			typedef struct _cap_struct *cap_t;

			cap_t cap_get_file(const char *path_p);
			int cap_set_file(const char *path_p, cap_t cap_p);

			cap_t cap_get_fd(int fd);
			int cap_set_fd(int fd, cap_t caps);

			cap_t cap_from_text(const char *buf_p);
			char *cap_to_text(cap_t caps, ssize_t *length_p);

			int cap_free(void *obj_d);
		'''
		self.ffi.cdef(cdef)

		self.libcap = self.ffi.verify('''
			#include <sys/types.h>
			#include <sys/capability.h>
		''', libraries=['cap'])

	def get_file(self, src):
		if isinstance(src, types.StringTypes): func = self.libcap.cap_get_file
		else:
			if not isinstance(src, (int, long)): src = src.fileno()
			func = self.libcap.cap_get_fd

		caps = func(src)
		try:
			if caps == self.ffi.NULL:
				if self.ffi.errno == errno.ENODATA: return ''
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))
			else:
				caps_len_p = self.ffi.new('ssize_t *')
				caps_p = self.libcap.cap_to_text(caps, caps_len_p)
				if caps_p == self.ffi.NULL:
					raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))
			return self.ffi.string(caps_p, caps_len_p[0])

		finally:
			if caps != self.ffi.NULL and self.libcap.cap_free(caps):
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

	def set_file(self, dst, caps_str):
		caps = self.libcap.cap_from_text(caps_str)
		if caps == self.ffi.NULL:
			raise ValueError('Invalid capabilities specification: {!r}'.format(caps_str))

		try:
			if isinstance(dst, types.StringTypes):
				err = self.libcap.cap_set_file(dst, caps)
			else:
				if not isinstance(dst, (int, long)): dst = dst.fileno()
				err = self.libcap.cap_set_fd(dst, caps)
			if err: raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))

		finally:
			if self.libcap.cap_free(caps):
				raise OSError(self.ffi.errno, os.strerror(self.ffi.errno))


class StrCaps(CStrCaps): pass



class XMetaHandler(object):

	def __init__(self):
		self.acl = StrACL()
		self.caps = StrCaps()

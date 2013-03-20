#-*- coding: utf-8 -*-

import itertools as it, operator as op, functools as ft
from urllib import urlencode, quote
from mimetypes import guess_type
from collections import Mapping
import os, sys, io, re, types, json

from OpenSSL import crypto
from zope.interface import implements
from lya import AttrDict

from twisted.web.iweb import IBodyProducer, UNKNOWN_LENGTH
from twisted.web.client import Agent, RedirectAgent,\
	HTTPConnectionPool, HTTP11ClientProtocol, ContentDecoderAgent,\
	GzipDecoder, FileBodyProducer, ResponseDone
from twisted.web.http_headers import Headers
from twisted.web import http
from twisted.protocols.basic import LineReceiver
from twisted.internet import defer, reactor, ssl, task, protocol

import logging
log = logging.getLogger(__name__)



class DataReceiver(protocol.Protocol):

	def __init__(self, done):
		self.done, self.data = done, list()

	def dataReceived(self, chunk):
		self.data.append(chunk)

	def connectionLost(self, reason):
		self.done.callback(b''.join(self.data)\
			if isinstance(reason.value, ResponseDone) else reason)


class LineQueue(LineReceiver):

	delimiter = b'\n'
	MAX_LENGTH = 2**20

	def __init__(self, done, queue):
		self.done, self.queue = done, queue

	def lineReceived(self, line):
		self.queue.put(line.strip())

	def connectionLost(self, reason):
		self.done.callback(
			None if isinstance(reason.value, ResponseDone) else reason )



class MultipartDataSender(object):
	implements(IBodyProducer)

	#: Single read/write size
	chunk_size = 64 * 2**10 # 64 KiB

	def __init__(self, fields, boundary):
		self.fields, self.boundary = fields, boundary
		self.task = None

		## "Transfer-Encoding: chunked" doesn't work with SkyDrive,
		##  so calculate_length() must be called to replace it with some value
		self.length = UNKNOWN_LENGTH

	def calculate_length(self):
		d = self.send_form()
		d.addCallback(lambda length: setattr(self, 'length', length))
		return d

	@defer.inlineCallbacks
	def upload_file(self, src, dst):
		try:
			while True:
				chunk = src.read(self.chunk_size)
				if not chunk: break
				yield dst.write(chunk)
		finally: src.close()

	@defer.inlineCallbacks
	def send_form(self, dst=None):
		dry_run = not dst
		if dry_run: dst, dst_ext = io.BytesIO(), 0

		for name, data in self.fields.viewitems():
			dst.write(b'--{}\r\n'.format(self.boundary))

			if isinstance(data, tuple):
				fn, data = data
				ct = guess_type(fn)[0] or b'application/octet-stream'
				dst.write(
					b'Content-Disposition: form-data;'
					b' name="{}"; filename="{}"\r\n'.format(name, fn) )
			else:
				ct = b'text/plain'
				dst.write( b'Content-Disposition:'
					b' form-data; name="{}"\r\n'.format(name) )
			dst.write(b'Content-Type: {}\r\n\r\n'.format(ct))

			if isinstance(data, types.StringTypes): dst.write(data)
			elif not dry_run: yield self.upload_file(data, dst)
			else: dst_ext += os.fstat(data.fileno()).st_size
			dst.write(b'\r\n')

		dst.write(b'--{}--\r\n'.format(self.boundary))

		if dry_run: defer.returnValue(dst_ext + len(dst.getvalue()))
		else: self.task = None

	def startProducing(self, dst):
		if not self.task: self.task = self.send_form(dst)
		return self.task

	def resumeProducing(self):
		if not self.task: return
		self.task.unpause()

	def pauseProducing(self):
		if not self.task: return
		self.task.pause()

	def stopProducing(self):
		if not self.task: return
		self.task.cancel()
		self.task = None


class ChunkingFileBodyProducer(object):
	implements(IBodyProducer)

	#: Single read/write size
	chunk_size = 64 * 2**10 # 64 KiB

	def __init__(self, src):
		self.src = src
		self.task = None
		self.length = UNKNOWN_LENGTH

	@defer.inlineCallbacks
	def upload_file(self, src, dst):
		try:
			while True:
				chunk = src.read(self.chunk_size)
				if not chunk: break
				yield dst.write(chunk)
		finally: src.close()

	def startProducing(self, dst):
		if not self.task: self.task = self.upload_file(self.src, dst)
		return self.task

	def resumeProducing(self):
		if not self.task: return
		self.task.unpause()

	def pauseProducing(self):
		if not self.task: return
		self.task.pause()

	def stopProducing(self):
		if not self.task: return
		self.task.cancel()
		self.task = None



class TLSContextFactory(ssl.CertificateOptions):

	isClient = 1

	def __init__(self, ca_certs_files):
		ca_certs = dict()

		for ca_certs_file in ( [ca_certs_files]
				if isinstance(ca_certs_files, types.StringTypes) else ca_certs_files ):
			with open(ca_certs_file) as ca_certs_file:
				ca_certs_file = ca_certs_file.read()
			for cert in re.findall( r'(-----BEGIN CERTIFICATE-----'
					r'.*?-----END CERTIFICATE-----)', ca_certs_file, re.DOTALL ):
				cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
				ca_certs[cert.digest('sha1')] = cert

		super(TLSContextFactory, self).__init__(verify=True, caCerts=ca_certs.values())

	def getContext(self, hostname, port):
		return super(TLSContextFactory, self).getContext()



class QuietHTTP11ClientFactory(protocol.Factory):
	noisy = False
	def __init__(self, quiescentCallback):
		self._quiescentCallback = quiescentCallback
	def buildProtocol(self, addr):
		return HTTP11ClientProtocol(self._quiescentCallback)


class QuietHTTPConnectionPool(HTTPConnectionPool):
	_factory = QuietHTTP11ClientFactory


class HTTPClientError(Exception):
	def __init__(self, code, msg):
		super(HTTPClientError, self).__init__(code, msg)
		self.code = code

class HTTPClient(object):

	#: Options to twisted.web.client.HTTPConnectionPool
	request_pool_options = dict(
		maxPersistentPerHost=10,
		cachedConnectionTimeout=600,
		retryAutomatically=True )

	#: Settings for a simple retry mechanism on http error codes
	retry = None

	#: Path string or list of strings
	ca_certs_files = b'/etc/ssl/certs/ca-certificates.crt'

	#: Dump HTTP request data in debug log (insecure!)
	debug_requests = False


	def __init__(self, **config):
		for k, v in config.viewitems():
			try: x = getattr(self, k)
			except AttributeError:
				raise AttributeError('Unrecognized configuration key: {}'.format(k))
			if isinstance(x, Mapping) and isinstance(v, Mapping):
				v = AttrDict(v)
				v.rebase(AttrDict(x))
			setattr(self, k, v)

		pool = QuietHTTPConnectionPool(reactor, persistent=True)
		for k, v in self.request_pool_options.viewitems():
			getattr(pool, k) # to somewhat protect against typos
			setattr(pool, k, v)
		self.request_agent = ContentDecoderAgent(RedirectAgent(Agent(
			reactor, TLSContextFactory(self.ca_certs_files), pool=pool )), [('gzip', GzipDecoder)])


	@defer.inlineCallbacks
	def request_with_retries(self, url, method, **request_kwz):
		'''Gets repeated if any of "raise_for" errors or HTTPClientError is raised.
			When number of attempts runs out, raises last error.'''
		assert 'url' not in request_kwz and 'method' not in request_kwz
		request_kwz['url'], request_kwz['method'] = url, method

		# Shortcut for simple cases
		if not self.retry or self.retry.attempts <= 1:
			defer.returnValue((yield self.request(**request_kwz)))

		retry_on = [HTTPClientError]
		for cls in request_kwz.get('raise_for', dict()).viewvalues():
			assert issubclass(cls, Exception), cls
			retry_on.append(cls)

		if isinstance(self.retry.delay, (tuple, list)):
			delays = list(self.retry.delay)
			for i in xrange(self.retry.attempts - len(delays), 1):
				delays.append(delays[-1])
		else: delays = [float(self.retry.delay)] * (self.retry.attempts - 1)
		delays = list(reversed(delays))

		while True:
			try: defer.returnValue((yield self.request(**request_kwz)))
			except tuple(retry_on) as err:
				if not delays: raise # no attempts left
				delay, d = delays.pop(), defer.Deferred()
				reactor.callLater(delay, d.callback, None)
				if self.debug_requests:
					log.debug( 'Introducing delay after failed'
						' ({}: {}) request: {}s'.format(type(err), err, delay) )
				yield d


	@defer.inlineCallbacks
	def request( self, url, method='get', decode=None,
			encode=None, data=None, chunks=True, headers=dict(),
			raise_for=dict(), queue_lines=None ):
		'''Make HTTP(S) request.
			decode (response body) = None | json
			encode (data) = None | json | form | files'''
		if self.debug_requests:
			log.debug( 'HTTP request: {} {} (h: {}, enc: {}, dec: {}, data: {!r})'\
				.format(method, url[:100], headers, encode, decode, data) )
		method, body = method.lower(), None
		headers = dict() if not headers else headers.copy()
		headers.setdefault('User-Agent', 'lafs-backup-tool')

		if data is not None:
			if encode == 'files':
				boundary = os.urandom(16).encode('hex')
				headers.setdefault('Content-Type', 'multipart/form-data; boundary={}'.format(boundary))
				data = MultipartDataSender(data, boundary)
				yield data.calculate_length()
			else:
				if encode is None:
					if isinstance(data, types.StringTypes): data = io.BytesIO(data)
				elif encode == 'form':
					headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
					data = io.BytesIO(urlencode(data))
				elif encode == 'json':
					headers.setdefault('Content-Type', 'application/json')
					data = io.BytesIO(json.dumps(data))
				else: raise ValueError('Unknown request encoding: {}'.format(encode))
				data = (ChunkingFileBodyProducer if chunks else FileBodyProducer)(data)

		if isinstance(url, unicode): url = url.encode('utf-8')
		if isinstance(method, unicode): method = method.encode('ascii')

		code = None
		try:
			res = yield self.request_agent.request(
				method.upper(), url,
				Headers(dict((k,[v]) for k,v in (headers or dict()).viewitems())), data )
			code = res.code
			if self.debug_requests:
				log.debug( 'HTTP request done ({} {}): {} {} {}'\
					.format(method, url[:100], code, res.phrase, res.version) )
			if code in raise_for: raise HTTPClientError(code, res.phrase)
			if code == http.NO_CONTENT: defer.returnValue(None)
			if code not in [http.OK, http.CREATED]: raise HTTPClientError(code, res.phrase)

			data = defer.Deferred()
			if queue_lines is None: res.deliverBody(DataReceiver(data))
			else: res.deliverBody(LineQueue(data, queue_lines))

			data = yield data
			assert decode in ['json', None], decode
			defer.returnValue(json.loads(data) if decode is not None else data)

		except HTTPClientError as err:
			raise raise_for.get(code, HTTPClientError)(code, err.message)

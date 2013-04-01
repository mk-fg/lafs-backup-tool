#-*- coding: utf-8 -*-
from __future__ import print_function

# Mostly adapted from tahoe-lafs code,
#  which was in turn taken from Brian Warner's buildbot code

import itertools as it, operator as op, functools as ft
import binascii

from twisted.cred import portal
from twisted.conch import manhole, telnet, manhole_ssh, checkers as conchc
from twisted.conch.ssh import keys
from twisted.conch.insults import insults
from twisted.internet import reactor, endpoints, defer
from twisted.application import strports


class AuthorizedKeysChecker(conchc.SSHPublicKeyDatabase):

	def __init__(self, authorized_keys):
		'''Keys must be base64-encoded openssh strings
			(optinally prefixed by key type and with "user@host" at the end).'''
		self.authorized_keys = set()
		for key in authorized_keys:
			key = key.split(None, 2)
			self.authorized_keys.add(
				binascii.a2b_base64(key[1 if len(key) > 1 else 0]) )

	def checkKey(self, credentials):
		for key in self.authorized_keys:
			if key == credentials.blob: return True
		return False


class ModifiedColoredManhole(manhole.ColoredManhole):

	def __init__(self, namespace):
		super(ModifiedColoredManhole, self).__init__()
		self.namespace = namespace # allow further modification of the dict

	def connectionMade(self):
		manhole.ColoredManhole.connectionMade(self)
		# look in twisted.conch.recvline.RecvLine for hints
		self.keyHandlers["\x08"] = self.handle_BACKSPACE
		self.keyHandlers["\x15"] = self.handle_KILLLINE
		self.keyHandlers["\x01"] = self.handle_HOME
		self.keyHandlers["\x04"] = self.handle_DELETE
		self.keyHandlers["\x05"] = self.handle_END
		self.keyHandlers["\x0b"] = self.handle_KILLLINE # really kill-to-end
		#self.keyHandlers["\xe2"] = self.handle_BACKWARDS_WORD # M-b
		#self.keyHandlers["\xe6"] = self.handle_FORWARDS_WORD # M-f

	def handle_KILLLINE(self):
		self.handle_END()
		for i in range(len(self.lineBuffer)):
			self.handle_BACKSPACE()


class CustomKeysConch(manhole_ssh.ConchFactory):

	def __init__(self, portal, server_keys=None):
		self.portal = portal
		if server_keys:
			for k,v in it.izip(['publicKeys', 'privateKeys'], server_keys):
				setattr(self, k, {'ssh-rsa': keys.Key.fromString(v)})


def build_service(endpoint, authorized_keys, server_keys=None, namespace=dict()):
	realm = manhole_ssh.TerminalRealm()
	realm.chainedProtocolFactory = lambda:\
		insults.ServerProtocol(ModifiedColoredManhole, namespace)
	factory = CustomKeysConch(
		portal.Portal(realm, [AuthorizedKeysChecker(authorized_keys)]), server_keys )
	return strports.service(endpoint, factory)

#!/usr/bin/python
# Copyright 2012 Ahmed (OneOfOne) Wahed, check COPYING for the license info.

from __future__ import print_function
from hashlib import sha1, md5
import os.path as osp
import json, base64
from subprocess import check_output
from ftplib import FTP
import sys, os, re
from zlib import compress as gzcompress, decompress as gzuncompress
from threading import Thread, current_thread
from collections import OrderedDict

try: # Assume python 2.x by default, then try to use python 3 imports.
	from Queue import Queue
	from ConfigParser import SafeConfigParser as ConfigParser
	from urlparse import urlparse
	from urllib import urlencode
	from urllib2 import Request, urlopen, URLError
except ImportError:
	from queue import Queue
	from urllib.parse import urlparse
	from urllib.parse import urlencode
	from urllib.request import Request, urlopen
	from urllib.error import URLError

__version__ = 0.9

DEVNULL = open('/dev/null', 'wb')
def _exec(args, strip_all = True):
	if not isinstance(args, list):
		args = args.split(' ')
	output = check_output(args).decode('utf-8').strip().split('\n')
	if strip_all:
		output = [p.strip() for p in output]
	return list(filter(None, output))

def sha1_file(fname):
	h = sha1()
	with open(fname, 'rb') as f:
		while True:
			data = f.read(8196)
			if not data:
				break
			h.update(data)
	return h.hexdigest()

def sha1_str(s):
	return sha1(s.encode('utf-8')).hexdigest()

def _ftp_mktree(ftp, fp):
	parts = fp.strip('/').split('/')[:-1]
	path = '/'
	for p in parts:
		path += p + '/'
		try:
			ftp.mkd(path)
		except: pass
	pwd = ftp.pwd()
	try:
		ftp.cwd(path)
	except:
		return False
	ftp.cwd(pwd)
	return True

def _fpath(fn):
	f = osp.realpath(osp.normpath(fn))
	if not osp.exists(f):
		raise IOError("%s doesn't exist." % f)
	return f

def _spath(root, base, fn):
	rb = osp.join(root, base)
	rp = osp.realpath(osp.normpath(osp.join(base, fn)))
	if rp[0:len(rb)] != rb:
		raise IOError('%s is not a child of %s.' % (rp, rb))
	return rp[len(rb):]

def _err(*args):
	print('ERROR', args, file=sys.stderr)

def _dvcs_root(dvcs_type):
	if dvcs_type == 'git':
		return _exec('git rev-parse --show-toplevel')[0]
	elif dvcs_type == 'hg':
		return _exec('hg root')[0]
	else:
		raise RemoteHelperException('Unknown dvcs_type')

def _detect_dvcs():
	cwd = os.getcwd()
	try: return ['hg', osp.exists('.hg/') and cwd or _dvcs_root('hg')]
	except: pass

	try: return ['git', osp.exists('.git/') and cwd or _dvcs_root('git')]
	except: pass

	raise RemoteHelperException('Currently only support git or hg repos.')

#from http://code.activestate.com/recipes/577187-python-thread-pool/ kinda
class ThreadPool(object):
	def __init__(self, num):
		self.q = Queue(num)
		for i in range(num):
			PoolWorker(self.q, i+1)

	def close(self): #dummy
		pass

	def join(self):
		self.q.join()

	def apply(self, func, args, callback):
		self.q.put((func, args, callback))

class PoolWorker(Thread):
	"""Thread executing tasks from a given tasks queue"""
	def __init__(self, q, id_):
		super(PoolWorker, self).__init__(name='%02i' % id_)
		self.q = q
		self.daemon = True
		self.start()

	def run(self):
		while True:
			func, args, cb = self.q.get()
			try:
				cb(func(*args))
			except BaseException as e:
				_err('PoolWorker-%s' % self.name, e)
			self.q.task_done()

def _tid():
	return 't%s' % current_thread().name

class Properties(OrderedDict):
	def read(self, fn):
		with open(fn, 'rb') as f:
			return self.loads(f.read().decode('utf-8'))
	load = read
	def write(self, fn):
		with open(fn, 'wb') as f:
			f.write(self.dumps().encode('utf-8'))
		return self
	dump = write
	def loads(self, data):
		data = data.split('\n')
		for line in data:
			line = line.strip()
			if not line or line[0] == '#' or line.find('=') == -1:
				continue
			k, v = line.split('=', 1)
			self.__setitem__(k.strip(), self._get_real_value(v.strip()))
		return self

	def dumps(self):
		ret = []
		for k, v in self.items():
			ret.append('%s = %s' % (k, v))
		return '\n'.join(ret) + '\n'

	def __getattr__(self, k):
		if k[0] == '_':
			return super(OrderedDict, self).__getattr__(k)
		return self.__getitem__(k)

	def __setattr__(self, k, v):
		if k[0] == '_':
			return super(OrderedDict, self).__setattr__(k, v)
		return self.__setitem__(k, v)

	def _get_real_value(self, v):
		try: return int(v)
		except: pass
		try: return float(v)
		except: pass
		if v.lower() == 'true': return True
		if v.lower() == 'false': return True
		return v

class RemoteHelper(object):
	def __init__(self, config):
		self.cfg = config

	def status(self, rev, files, nocheck):
		hfiles = {}
		if files:
			for f in self.changed_files(files):
				if not osp.isfile(f):
					continue
				sp = _spath(self.cfg.root, self.cfg.base, f)
				hfiles[sp] = Properties(php_writable=False, fpath=f, hash=sha1_file(f))
		else:
			for f in self.dvcs_changed_files(rev):
				sp = _spath(self.cfg.root, self.cfg.base, f)
				hfiles[sp] = Properties(php_writable=False, fpath=f, hash=sha1_file(f))

		yield len(hfiles), None
		if nocheck:
			yield len(hfiles), hfiles
		else:
			ret = self.check(hfiles)
			yield len(ret), ret

	def check(self, files):
		data =  {'files': list(files.keys())}
		d = self.get_json('check', data)
		if 'error' in d:
			_err('check', 'ERROR! Server returned : %s' % d['error'])
			return None

		ret = {}
		for f, props in files.items():
			rdata = d[f]
			if rdata[0] != props.hash:
				props.php_writable = rdata[1]
				props.rhash = rdata[0]
				ret[f] = props
		return ret

	def push(self, files, cb):
		prefer_php = self.cfg.method in ('php', 'auto')
		pool = ThreadPool(self.cfg.threads)
		try:
			for f, props in files.items():
				self._debug('push', f, props.php_writable, prefer_php)
				if props.php_writable and prefer_php: #single threaded for now
					args = (f, props.fpath, props.hash)
					pool.apply(self._http_push, args, callback=cb)
				else:
					args = (f, props.fpath)
					pool.apply(self._ftp_push, args, callback=cb)
		except BaseException as e:
			print('push error = ', e)
			#pool.terminate()
		finally:
			pool.join()
		return True

	def pull(self, files, cb):
		prefer_php = self.cfg.method in ('php', 'auto')
		pool = ThreadPool(self.cfg.threads)
		try:
			for f, props in files.items():
				self._debug('push', f, props.php_writable, prefer_php)
				if prefer_php:
					args = (f, props.fpath, props.hash)
					pool.apply(self._http_pull, args, callback=cb)
				else:
					args = (f, props.fpath)
					pool.apply(self._ftp_pull, args, callback=cb)
		except BaseException as e:
			print('push error = ', e)
			#pool.terminate()
		finally:
			pool.join()
		return True

	def get_json(self, action, data = {}):
		data =  dict({'action': action, 'auth': self.cfg.auth}, **data)
		d = json.dumps(data, separators=(',',':')).encode('utf-8')
		# str(self.cfg.url) because python 2.7 is stupid, http://code.google.com/p/reviewboard/issues/detail?id=2155
		req = Request(str(self.cfg.url), data=gzcompress(d,9))
		res = urlopen(req).read()
		self._debug('get_json', d, res)
		res = gzuncompress(res)
		ret = json.loads(res.decode('utf-8'))
		self._debug('get_json', ret)
		return ret

	def changed_files(self, files):
		return [_fpath(fn) for fn in files]

	def hg_changed_files(self, rev):
		if rev == 'ALL':
			rev = '0:tip'
		if rev:
			rev = '--rev %s' % rev
		else:
			rev = ''
		cmd = 'hg --color never status %s -ma %s' % (osp.join(self.cfg.root, self.cfg.base), rev)

		files = [f.split(' ')[1] for f in _exec(cmd.split(' ')) if f[0].lower() in ('m', 'a')]
		return [_fpath(f) for f in files]

	def git_changed_files(self, rev = '-2'):
		if rev == 'ALL':
			rev = '??'
		else:
			rev = ''
		cmd = 'git log --name-status --oneline %s -- %s' % (rev, osp.join(self.cfg.root, self.cfg.base))

		files = [f.split(' ')[1] for f in _exec(cmd.split(' ')) if f[0].lower() in ('m', 'a')]
		return [_fpath(f) for f in files]

	def dvcs_changed_files(self, rev):
		dvcs = self.cfg.dvcs
		if dvcs == 'git':
			return self.git_changed_files(rev)
		elif dvcs == 'hg':
			return self.hg_changed_files(rev)
		raise RemoteHelperException('Unknown dvcs : %s' % dvcs)

	def _http_push(self, f, fn, h): #http pusher
		try:
			data = {}
			data['file'] = f
			with open(fn, 'rb') as fdata:
				data['data'] = base64.b64encode(fdata.read()).decode('utf-8')
			resp = self.get_json('push', data)
			if 'error' in resp:
				return (_tid(), 'php', f, 'failed, error = %s' % resp['error'])
			else:
				return (_tid(), 'php', f, resp[f] == h and 'success' or 'failed')
		except BaseException as e:
			return (_tid(), 'php', f, 'error : %s' % repr(e))

	def _http_pull(self, f, fn, h):
		try:
			data = {}
			data['file'] = f
			resp = self.get_json('pull', data)
			if 'error' in resp:
				return (_tid(), 'php', f, 'failed, error = %s' % resp['error'])
			else:
				resp = resp[f]
				with open(fn, 'wb') as fdata:
					fdata.write(base64.b64decode(resp['data'].encode('utf-8')))
				return (_tid(), 'php', f, resp['hash'] == sha1_file(fn) and 'success' or 'failed')
		except BaseException as e:
			return (_tid(), 'php', f, 'error : %s' % repr(e))

	def _ftp_push(self, remoteFn, localFn):
		fi = urlparse(self.cfg.ftp)
		try:
			ftp = FTP()

			port = fi.port or 21

			ftp.connect(fi.hostname, port)
			ftp.login(fi.username, fi.password)

			rf = osp.join(fi.path or '/', remoteFn.strip('/'))

			ret = False
			try:
				ret = ftp.storbinary('STOR ' + rf, open(localFn, 'rb'))
			except:
				#_debug('ftp_put (%d)' % _tid(), 'Folder for "%s" does not exist, trying to mktree : %s' % (rf, _ftp_mktree(ftp, rf)))
				_ftp_mktree(ftp, rf)
				ret = ftp.storbinary('STOR ' + rf, open(localFn, 'rb'))
			return (_tid(), 'ftp', remoteFn, ret[0:3] == '226' and 'success' or ret)
		except BaseException as e:
			return (_tid(), 'ftp', remoteFn, 'error : %s' % repr(e))

	def _ftp_pull(self, remoteFn, localFn):
		fi = urlparse(self.cfg.ftp)

		try:
			ftp = FTP()

			port = fi.port or 21

			ftp.connect(fi.hostname, port)
			ftp.login(fi.username, fi.password)

			rf = osp.join(fi.path or '/', remoteFn.strip('/'))

			#_debug('ftp_pull', '(%d)' % _tid(), 'Pulling "%s" to "%s"' % (rf, lf))
			ret = False
			with open(localFn, 'wb') as outfile:
				ret = ftp.retrbinary('RETR ' + rf, outfile.write)
			#print('%5d\t%60s\t%6s' % (_tid(), remotef, ret[0:3] == '226' and 'success' or ret))
			return (_tid(), 'ftp', remoteFn, ret[0:3] == '226' and 'success' or ret)
		except BaseException as e:
			return (_tid(), 'ftp', remoteFn, 'error : %s' % repr(e))

	def _debug(self, *args):
		if self.cfg.debug:
			with open('/dev/stderr', 'w') as stderr:
				print('DEBUG', *args, file=stderr)


class RemoteHelperException(BaseException):
	pass

def main():
	import argparse
	parser = argparse.ArgumentParser(argument_default=argparse.SUPPRESS, prog='dvcs-helper')

	parser.add_argument('-c', '--config', default=None,
		help='path to the config file to use [default: dvcs-root/.dvcs-helper]')

	parser.add_argument('--dvcs', choices=['git', 'hg', 'auto'],
		default='auto',
		help='which dvcs to use [default: auto]')

	parser.add_argument('-d', '--debug', action='store_true', default=False,
		help='path to the config file to use, default is $PWD/.dvcshelper')

	parser.add_argument('-v', '--version', action='version',
		version='%(prog)s v' + str(__version__))


	subp = parser.add_subparsers(title='commands', help='Sub commends: ', dest='cmd')

	cmd_status = subp.add_parser('status', help='Show the working tree status')
	cmd_status.add_argument('-f', '--force', action='store_true',
		help='just check locally, do not call the remote php helper.')

	cmd_status.add_argument('-r', '--rev', help='revision to check against.')

	cmd_status.add_argument('files', nargs='*',
		help='files to pull or the dvs revision to compare against.')

	#push

	cmd_push = subp.add_parser('push', help='push files to the remote server.')

	cmd_push.add_argument('-f', '--force', action='store_true',
		help='Force pushing without calling the php helper.')

	cmd_push.add_argument('-r', '--rev',
		help='revision to check against and push to the remote host.')

	cmd_push.add_argument('files', nargs='*',
		help='files to push or the dvs revision to compare against.')

	#pull
	cmd_pull = subp.add_parser('pull', help='Show the working tree status')

	cmd_pull.add_argument('-f', '--force', action='store_true',
		help='Force pulling without calling the php helper.')

	cmd_pull.add_argument('-r', '--rev',
		help='revision to check against and pull from the remote host.')

	cmd_pull.add_argument('files', nargs='*',
		help='files to pull or the dvs revision to compare against.')

	#config
	cmd_config = subp.add_parser('config', help='Generate a config file.')

	cmd_config.add_argument('-u', '--url', type=str, default='http://example.com/dvcs-helper.php',
		help='The URL of the php helper script.');

	cmd_config.add_argument('-f', '--ftp', type=str, default='ftp://user:pass@example.com/test',
		help='The FTP url to use in case http pushing does not work. [example: ftp://user:pass@example.com/test]');

	cmd_config.add_argument('-b', '--base', type=str, default='./',
		help='where are the pushable/pullable files stored under version control.')

	cmd_config.add_argument('-m', '--method', choices=['ftp', 'php', 'auto'],
		default='auto',
		help='How to push/pull, defaults to auto try php then ftp.')

	cmd_config.add_argument('-t', '--threads', type=int, default=4,
		help='Number of threads to use for pushing/pulling [default: 4]');

	cmd_config.add_argument('-a', '--auth', type=str,
		help='Authorization key to pass to the php helper.');

	cmd_config.add_argument('-w', '--write-config', nargs='?',
		default='/dev/stdout',
		help='writes the config to a file [default: dvcs-root/.dvcs-helper]' )

	cmd_php = subp.add_parser('php', help='Generate the php helper using the current auth key.')

	cmd_php.add_argument('-w', '--write-php', nargs='?',
		default='/dev/stdout',
		help='writes the helper to a file [default: base/helper.php]' )

	cmd_php.add_argument('-k', '--auth-key', action='store_true',
		help='prints the php auth key and exits.')

	args = parser.parse_args()
	if args.dvcs == 'auto':
		dvcs = _detect_dvcs()
	else:
		dvcs = [args.dvcs, _dvcs_root(args.dvcs)]

	args.config = args.config or osp.join(dvcs[1], '.dvcs-helper')
	if args.cmd == 'config':
		print(args)
		config = Properties()
		config.url = args.url
		config.ftp = args.ftp
		config.base = args.base
		config.threads = args.threads
		config.method = args.method
		config.dvcs = dvcs[0]

		if args.auth is None:
			import time, random
			t = time.time()
			args.auth = 'dvcs-helper:%0.1f:%f' % (__version__, random.uniform(1,t))
		config.auth = args.auth

		if args.write_config is None:
			args.write_config = args.config

		config.write(args.write_config)
		print('Config file saved as %s' % args.write_config)
	else:
		config = Properties()
		config.read(args.config)
		config.debug = args.debug
		config.root = dvcs[1]

		config.debug = args.debug
		if args.cmd == 'php':
			key = sha1_str(config.auth)
			if args.auth_key:
				print(key)
				sys.exit(0)

			fp = osp.join(osp.dirname(__file__), 'helper.php')
			with open(fp, 'r') as php:
				code = php.read().replace('%AUTH_HASH%', key)
			with open(args.write_php, 'w') as php:
				php.write(code)
			print('PHP helper saved as : %s' % args.write_php)
			sys.exit(0)

		rh = RemoteHelper(config)

		changed_files = None

		rh._debug('args', args)
		rh._debug('config', config)
		for n, files in rh.status(args.rev, args.files, args.force):
			if files is None:
				print('Checking %d file(s) for changes...' % n)
			else:
				if not n:
					parser.exit('nothing changed')
				changed_files = files

		if args.cmd == 'status':
			print('%d file(s) changed : ' % len(changed_files))
			for f in changed_files:
				print("M\t%s" % f)

		elif args.cmd == 'push':
			print('Pushing %d file(s): ' % len(changed_files))
			print(' %3s | %6s | %-60s | %s' % ('tid', 'method', 'file', 'status'))
			rh.push(changed_files, print_files)

		elif args.cmd == 'pull':
			print('Pulling %d file(s): ' % len(changed_files))
			print(' %3s | %6s | %-60s | %s' % ('tid', 'method', 'file', 'status'))
			rh.pull(changed_files, print_files)

def print_files(args):
	pid, method, fn, status = args
	print(' %3s |  %s   | %-60s | %s' % (pid, method, fn, status))

if __name__ == '__main__':
	main()

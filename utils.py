from __future__ import print_function
import time
import logging
from os.path import isfile, getsize, basename
from logging import getLogger

PRINT_LOG = True
LOG_LEVEL = logging.DEBUG

log = getLogger("hubic_client")
log.setLevel(LOG_LEVEL)
if PRINT_LOG:
	ch = logging.StreamHandler()
	ch.setLevel(LOG_LEVEL)
	log.addHandler(ch)


# clem 30/08/2017
def timed(fun, *args):
	s = time.time()
	r = fun(*args)
	total_time = time.time() - s
	return r, total_time


# clem 30/08/2017
def waiter(message, wait_sec):
	message += '      \r'
	while wait_sec > 0:
		print(message % wait_sec, end='')
		wait_sec -= 1
		time.sleep(1)
	print()


# clem 30/08/2017 from line 6 @ https://goo.gl/BLuUFD 03/02/2016
def human_readable_byte_size(num, suffix='B'):
	if type(num) is not int:
		if isfile(num):
			num = getsize(num)
		else:
			raise TypeError('num should either be a integer file size, or a valid file path')
	for unit in ['', 'Ki', 'Mi', 'Gi', 'Ti', 'Pi', 'Ei', 'Zi']:
		if abs(num) < 1024.0:
			return "%3.1f%s%s" % (num, unit, suffix)
		num /= 1024.0
	return "%.1f%s%s" % (num, 'Yi', suffix)


# clem 30/08/2017
def compute_speed(file_path, transfer_time):
	if not transfer_time:
		return ''
	try:
		size = getsize(file_path)
		return human_readable_byte_size(int(size / transfer_time)) + '/s'
	except (IOError, FileNotFoundError):
		return ''


# clem 30/08/2017 form line 203 @ https://goo.gl/Wquh6Z clem 08/04/2016 + 10/10/2016
def this_function_caller_name(delta=0):
	""" Return the name of the calling function's caller

	:param delta: change the depth of the call stack inspection
	:type delta: int

	:rtype: str
	"""
	import sys
	return sys._getframe(2 + delta).f_code.co_name if hasattr(sys, "_getframe") else ''


# clem 30/08/2017 from line 154 @ https://goo.gl/PeiZDk 19/05/2016
def get_key(name=''):
	secrets_root = '.secret/'
	if name.endswith('_secret'):
		name = name[:-7]
	if name.startswith('.'):
		name = name[1:]
	full_path = '%s.%s_secret' % (secrets_root, name)
	
	def read_key():
		with open(full_path) as f:
			log.debug('Read key %s from %s' % (full_path, this_function_caller_name(1)))
			return str(f.read())[:-1]
	
	try:
		return read_key()
	except Exception as e:
		log.exception(str(e))
		pass
	log.warning('could not read key %s from %s' % (name, secrets_root))
	return ''

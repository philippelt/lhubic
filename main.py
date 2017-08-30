#!/usr/bin/python3

import lhubic
from utils import *
# from swiftclient.exceptions import ClientException

HUBIC_TOKEN_FILE = '.hubic_token'
HUBIC_CLIENT_ID = get_key('hubic_api_id')
HUBIC_CLIENT_SECRET = get_key('hubic_api_secret')
_100_KiBi = 100 * 1024
_512_KiBi = 512 * 1024
_1_MiBi = 1 * 1024 * 1024
_2_MiBi = 2 * 1024 * 1024


class HubicClient(object):
	__hubic = None
	__auth_token = ''
	
	def __init__(self):
		if self._auth():
			self.save_token()
		
	@property
	def __token_connection_args(self):
		return {'client_id': HUBIC_CLIENT_ID, 'client_secret': HUBIC_CLIENT_SECRET, 'refresh_token': self._auth_token}
	
	@property
	def __creds_connection_args(self):
		return HUBIC_CLIENT_ID, HUBIC_CLIENT_SECRET, get_key('hubic_username'), get_key('hubic_password')
	
	@property
	def _auth_token(self):
		""" Reads and store auth token from HUBIC_TOKEN_FILE file, if exists
		
		:return: auth token or ''
		:rtype: str
		"""
		if not self.__auth_token and isfile(HUBIC_TOKEN_FILE):
			with open(HUBIC_TOKEN_FILE) as f:
				self.__auth_token = f.read()
			log.debug('read auth token from %s' % HUBIC_TOKEN_FILE)
		return self.__auth_token
	
	def _connect(self):
		""" Connect to hubic api service if not already connected, using either connection token, or credentials,
		
		and store the hubic connection object
		
		:return: is success
		:rtype: bool
		"""
		if not self.__hubic:
			if self._auth_token:
				log.debug('connection with auth token')
				self.__hubic = lhubic.Hubic(**self.__token_connection_args)
			else:
				log.debug('connection with account auth info')
				self.__hubic = lhubic.Hubic(*self.__creds_connection_args)
			return True
		return False
	
	@property
	def hubic(self):
		""" provide the Hubic object, with auto-connection
		
		:return: the hubic connection object
		:rtype: lhubic.Hubic
		"""
		self._connect()
		return self.__hubic
	
	def reset(self):
		""" clears the hubic connection object and saved auth token
		
		:return: is success
		:rtype: bool
		"""
		from os import remove
		try:
			self.__hubic.close()
			log.debug('connection closed')
		except Exception as e:
			log.warning(str(e))
		self.__hubic = None
		self.__auth_token = ''
		if isfile(HUBIC_TOKEN_FILE):
			remove(HUBIC_TOKEN_FILE)
		log.debug('auth token cleared')
		return True
	
	def _auth(self):
		""" Proceeds with authentication, clears token and try again on HubicTokenFailure
		
		:return: is success
		:rtype: bool
		"""
		try:
			self.hubic.os_auth() # To get an openstack swift token
			log.debug('connected')
			return True
		except lhubic.HubicTokenFailure:
			self.reset()
			return self._auth()
	
	def save_token(self):
		""" Save the content of refresh_token to get access without user/password in HUBIC_TOKEN_FILE file
		
		:return: is success
		:rtype: bool
		"""
		try:
			token = self.hubic.refresh_token
			if token != self.__auth_token:
				with open(HUBIC_TOKEN_FILE, 'w') as f:
					f.write(self.hubic.refresh_token)
				log.debug('auth token saved')
			return True
		except Exception as e:
			log.exception(e)
		return False
	
	def __up_down_stud(self, container, local_file_path, remote_file_path, up_or_down, measure_speed=True):
		def _upload_wrapper():
			total_size = getsize(local_file_path)
			total_size_str = human_readable_byte_size(total_size)
			with open(local_file_path, 'rb') as f:
				from time import sleep
				from concurrent.futures import ThreadPoolExecutor
				i = 0.
				interval = .25 # refresh interval
				io_timeout = (total_size / _100_KiBi) / interval # Timeout based on 100KiBi/s transfer speed
				with ThreadPoolExecutor(max_workers=1) as executor:
					future = executor.submit(self.hubic.put_object, container, remote_file_path, f)
					start = time.time()
					log.debug('uploading %s %s to %s' % (local_file_path, total_size_str, remote_file_path))
					while not future.done():
						read_position = f.tell()
						progress = (read_position / total_size) * 100
						elapsed = time.time() - start
						if read_position < total_size:
							current_speed_avg = human_readable_byte_size(int(read_position / elapsed))
						else:
							current_speed_avg = human_readable_byte_size(0)
						print('%.02i%% %s at avg %s/s        \r' %
							(progress, human_readable_byte_size(read_position), current_speed_avg), end='')
						i += 1.
						if i >= io_timeout:
							raise TimeoutError('Transfer exceeded maximum allowed time of %s sec' %
								str(io_timeout * interval))
						sleep(interval)
					
					file_md5 = future.result()
				return file_md5
			
		def _download_wrapper():
			header = self.hubic.head_object(container, remote_file_path)
			total_size = int(header.get('content-length', 0))
			total_size_str = human_readable_byte_size(total_size)
			if isfile(local_file_path):
				raise FileExistsError('File %s exist. For safety files will not be overwritten' % local_file_path)
			with open(local_file_path, 'wb') as f:
				# from time import sleep
				from concurrent.futures import ThreadPoolExecutor
				# i = 0.
				# interval = .25 # refresh interval
				# io_timeout = (total_size / _100_KiBi) / interval # Timeout based on 100KiBi/s transfer speed
				with ThreadPoolExecutor(max_workers=1) as executor:
					temp = dict()
					future = executor.submit(self.hubic.get_object, container, remote_file_path, response_dict=temp)
					# start = time.time()
					log.debug('downloading %s %s to %s' % (remote_file_path, total_size_str, local_file_path))
					
					header, content = future.result()
					f.write(content)
				return header.get('etag', '')
		
		try:
			func = _upload_wrapper if up_or_down == 'up' else _download_wrapper
			res = timed(func) if measure_speed else (func(), 0)
			
			sup = ''
			speed = compute_speed(local_file_path, res[1])
			if speed:
				sup = ' in %.02s sec, avg %s' % (res[1], speed)
			log.info('%s %s%s' % (local_file_path, res[0], sup))
		except Exception as e:
			log.error('ERROR: %s' % e)
	
	def upload(self, container, local_file_path, remote_file_path, measure_speed=True):
		self.__up_down_stud(container, local_file_path, remote_file_path, 'up', measure_speed)
	
	def download(self, container, local_file_path, remote_file_path, measure_speed=True):
		self.__up_down_stud(container, local_file_path, remote_file_path, 'down', measure_speed)
	

my_hubic = HubicClient()


# send_file = 'LICENSE.txt'
local_path = 'upload.deb'
target_path = 'test/%s' % basename(local_path)
my_hubic.download('default', local_path, target_path)
my_hubic.upload('default', local_path, target_path)
# my_hubic.download('default', '_%s' % local_path, 'target_path')

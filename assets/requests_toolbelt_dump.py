#!/usr/bin/python
# modified fork of dump.py from requests_toolbelt utilities
# https://github.com/requests/toolbelt/blob/master/requests_toolbelt/utils/dump.py

import collections
from requests import compat


_PrefixSettings = collections.namedtuple('PrefixSettings', ['request', 'response'])

class PrefixSettings(_PrefixSettings):
	def __new__(cls, request, response):
		return super(PrefixSettings, cls).__new__(cls, _coerce_to_bytes(request), _coerce_to_bytes(response))


def _format_header(name, value):
	return (_coerce_to_bytes(name) + b': ' + _coerce_to_bytes(value) + b'\r\n')

def _dump_response_data(response, prefixes, bytearr):
	prefix = prefixes.response
	version_str = {9: b'0.9', 10: b'1.0', 11: b'1.1'}.get(response.raw.version, b'?')
	
	# <prefix>HTTP/<version_str> <status_code> <reason>
	bytearr.extend(prefix + b'HTTP/' + version_str + b' ' + str(response.raw.status).encode('ascii') + b' ' + _coerce_to_bytes(response.reason) + b'\r\n')
	
	headers = response.raw.headers
	for name in headers.keys():
		for value in headers.getlist(name):
			bytearr.extend(prefix + _format_header(name, value))
	
	bytearr.extend(prefix + b'\r\n')
	bytearr.extend(response.content)

def _coerce_to_bytes(data):
	if not isinstance(data, bytes) and hasattr(data, 'encode'):
		data = data.encode('utf-8')
	return data if data is not None else b''

def dump_response(response, request_prefix=b'', response_prefix=b'', data_array=None):
	data = data_array if data_array is not None else bytearray()
	prefixes = PrefixSettings(request_prefix, response_prefix)
	
	_dump_response_data(response, prefixes, data)
	return data







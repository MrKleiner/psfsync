"""
Simple multiprocessed HTTP server.
"""

import threading
import socket
import urllib
import time
import sys

from urllib.parse import unquote as url_unquote
from dataclasses import dataclass, field

from .jag_util import *
from .mimes import RSP_CODE_MAP


RN_BYTES = b'\r\n'
RN_STR = '\r\n'
HSEP_BYTES = b': '
HSEP_STR = ': '

B_KB = 1024
B_MB = B_KB**2

REUSEPORT_AVAILABLE = hasattr(socket, 'SO_REUSEPORT')



def ERR_CON_RESET():
	return ConnectionResetError(
		'Connection terminated.'
	)



class NULL:
	pass



class JagErrCode(Exception):
	def __init__(self, message, code=500, fatal=True):
		super().__init__(message)
		self.message = message
		self.code = code
		self.fatal = fatal



class JagHeaders(NamedPrint):
	DEFAULT_HBUF_SIZE_LIMIT = 1024 * 256

	def __init__(self, hdict):
		self.hdict = hdict

	@staticmethod
	def ERR_TOO_LARGE():
		return ConnectionAbortedError(
			'Cannot collect header data further: '
			'The request is either invalid or too large.'
		)

	@staticmethod
	def jag_hname(hname):
		return (
			str(hname)
			.lower()
			.strip()
			.replace('-', ' ')
			.title()
			.replace(' ', '-')
		)

	@classmethod
	def from_skt(cls, skt_rfile, size_limit=None):
		size_limit = size_limit or cls.DEFAULT_HBUF_SIZE_LIMIT

		hbuf_size = 0
		hlines = []

		while True:
			if hbuf_size >= size_limit:
				raise cls.ERR_TOO_LARGE()

			line = skt_rfile.readline(size_limit - hbuf_size)

			# Any kind of socket read, which results into emptiness (b'')
			# means the connection has been terminated
			if not line:
				raise ERR_CON_RESET()

			# The shit HAS to end with \r\n
			if not line.endswith(RN_BYTES):
				raise cls.ERR_TOO_LARGE()

			if line == RN_BYTES:
				break

			hlines.append(
				line.decode()
			)

			hbuf_size += len(line)

		headers = cls.from_blank()
		for hline in hlines:
			hname, hval = hline.split(':', 1)
			headers.add(hname, hval.strip())

		return headers

	@classmethod
	def from_blank(cls, data=None):
		return cls(data or {})

	def send_to(self, skt_raw):
		skt_raw.sendall(
			self.to_bytes()
		)

	def to_printable(self, raw_lines=False):
		pad = 0
		for hname, hvals in self.hdict.items():
			if len(hname) > pad:
				pad = len(hname)

		lines = []
		for hname, hvals in self.hdict.items():
			for hval in hvals:
				lines.append(
					f'{str(hname).ljust(pad + 3)}: {str(hval)[0:150]}'
				)

		if raw_lines:
			return lines

		return '\n'.join(frame_lines(lines))

	def to_bytes(self):
		buf = []
		for hname, hvals in tuple(self.hdict.items()):
			for hval in tuple(hvals):
				buf.append(
					HSEP_STR.join((hname, str(hval)))
				)

		buf.append('')

		return RN_STR.join(buf).encode()

	def add(self, hname, hval):
		hname = self.jag_hname(hname)
		self.hdict.setdefault(hname, []).append(hval)

	def get_all(self, hname):
		return self.hdict.get(
			self.jag_hname(hname)
		)

	def set_all(self, hname, hvals):
		self.hdict[self.jag_hname(hname)] = list(hvals)

	def __getitem__(self, key):
		key = self.jag_hname(key)
		return self.hdict.get(key, (None,))[0]

	def __setitem__(self, key, val):
		key = self.jag_hname(key)
		if val == None:
			del self.hdict[key]
			return

		self.hdict[key] = [val]

	def __delitem__(self, key):
		key = self.jag_hname(key)

		if key in self.hdict:
			del self.hdict[key]

	def __contains__(self, key):
		key = self.jag_hname(key)
		return (
			key in self.hdict
		)



class JagQuery(NamedPrint):
	DEFAULT_QUERY_SIZE_LIMIT = 1024 * 256

	@staticmethod
	def ERR_TOO_LARGE():
		return ConnectionAbortedError(
			'Query line too large OR invalid.'
		)

	@classmethod
	def from_skt(cls, skt_rfile, size_limit=None):
		qstring = skt_rfile.readline(
			size_limit or cls.DEFAULT_QUERY_SIZE_LIMIT
		)

		if not qstring:
			raise ERR_CON_RESET()

		if not qstring.endswith(RN_BYTES):
			raise cls.ERR_TOO_LARGE()

		jag_query = cls()

		qstring = qstring.decode().strip()
		method, path, protocol = qstring.split(' ')
		parsed_url = urllib.parse.urlparse(path)

		jag_query.method = method

		jag_query.path = urllib.parse.unquote(parsed_url.path)

		jag_query.prms = {
			k:(''.join(v)) for (k, v)
			in urllib.parse.parse_qs(parsed_url.query, True).items()
		}

		return jag_query

	def to_printable(self):
		prm_lines = []

		pad = calc_string_pad(self.prms.keys())

		for prmname, prmval in self.prms.items():
			prm_lines.append(
				f'    {str(prmname).ljust(pad)} = {str(prmval)}'
			)

		qline = ' '.join((
			self.method,
			self.path[0:75],
		))

		return [qline, *prm_lines]



class HexenChunk(NamedPrint):
	def __init__(self, skt_rfile):
		self.skt_rfile = skt_rfile

		self._size = None
		self.prog = 0

	@property
	def size(self):
		if self._size != None:
			return self._size

		self._size = int(
			self.skt_rfile.readline(1024).strip(),
			16
		)

		# self._size = int.from_bytes(
		# 	bytes.fromhex(
		# 		self.skt_rfile.readline(1024)
		# 		.decode()
		# 		.strip()
		# 	)
		# )

		if self._size == 0:
			trailing_headers = JagHeaders.from_skt(self.skt_rfile)
			if len(trailing_headers.hdict):
				self.nprint(
					'Rare sighting of trailing headers:',
					trailing_headers.hdict,
				)

		return self._size

	@property
	def done(self):
		return self.prog >= self.size

	@property
	def final(self):
		return self.size == 0

	def read(self, cap=4096):
		if self.done or (cap <= 0):
			return b''

		data = self.skt_rfile.read(
			min(self.size - self.prog, cap)
		)

		if not data:
			raise ERR_CON_RESET()

		self.prog += len(data)

		if self.done:
			self.skt_rfile.read(2)

		return data



class ChunkedBodyReader(NamedPrint):
	def __init__(self, skt_rfile):
		self.skt_rfile = skt_rfile

		self.chunk = None
		self.done = False

	def read(self, cap=4096):
		if self.done or (cap <= 0):
			return b''

		while True:
			if not self.chunk:
				self.chunk = HexenChunk(self.skt_rfile)

			if self.chunk.final:
				self.done = True
				return b''

			if not (data := self.chunk.read(cap)):
				self.chunk = None
				continue

			return data



class BasicBodyReader(NamedPrint):
	def __init__(self, skt_rfile, size):
		self.skt_rfile = skt_rfile
		self.size = size
		self.prog = 0

	def read(self, cap=4096):
		if (self.prog >= self.size) or (cap <= 0):
			return b''

		data = self.skt_rfile.read(
			min(self.size - self.prog, cap)
		)

		if not data:
			raise ERR_CON_RESET()

		self.prog += len(data)

		return data



class ChunkedStream:
	def __init__(self, skt_raw):
		self.skt_raw = skt_raw

	def __enter__(self):
		return self

	def __exit__(self, e_type, e_val, e_trace):
		# todo: does this also have to be hex ?
		self.skt_raw.sendall(b'0' + RN_BYTES + RN_BYTES)

	def send(self, data):
		# Send the chunk size
		self.skt_raw.sendall(
			hex(len(data)).lstrip('0x').encode() + RN_BYTES
		)
		# Send the chunk itself
		self.skt_raw.sendall(data)
		# Send separator
		self.skt_raw.sendall(RN_BYTES)



class BasicStream:
	def __init__(self, skt_raw, total, must_finish=True):
		self.skt_raw = skt_raw
		self.total = total
		self.prog = 0
		self.must_finish = must_finish

	def __enter__(self):
		self.prog = 0
		return self

	def __exit__(self, e_type, e_val, e_trace):
		if self.must_finish and (self.total < self.prog):
			raise ValueError(
				f'The stream was supposed to fully finish, but '
				f'stopped at {self.prog}/{self.total}'
			)

		return

	def send(self, data):
		if self.prog >= self.total:
			return 0

		if (self.prog + len(data)) > self.total:
			data = data[0:self.total - self.prog]

		self.skt_raw.sendall(data)

		return len(data)



class ByteRange(NamedPrint):
	DEFAULT_CAP = B_MB * 3
	DEFAULT_CHUNK_SIZE = B_MB * 1

	def __init__(self, start, end):
		self.start = start
		self.end = end

	@classmethod
	def from_string(cls, byterange_str):
		if not str(byterange_str or '').startswith('bytes='):
			cls.nprint('Byte Range string empty:', byterange_str)
			return None

		_, range_values = byterange_str.split('=')
		ranges = range_values.split(',')

		cls.nprint('Ranges:', ranges)

		if len(ranges) != 1:
			# Fuck multiple ranges. Nobody uses them
			return None

		start, end = ranges[0].split('-')

		try:
			start = int(start)
		except:
			start = None

		try:
			end = int(end)
		except:
			end = None

		if ((end or 0) < 0) or ((start or 0) < 0):
			raise JagErrCode(
				f'Either start ({start}) or end ({end}) offset '
				f'is of negative size',
				code=416,
			)

		if start == None:
			return None

		return cls(start, end)

	@classmethod
	def from_req(cls, req):
		return cls.from_string(
			req.headers['range']
		)

	def stream_buf_to(self,
		buf,
		reply,
		content_type=None,
		cap=None,
		chunk_size=None,
		pass_through=None,
	):
		cap = cap or self.DEFAULT_CAP
		chunk_size = chunk_size or self.DEFAULT_CHUNK_SIZE

		buf_len = buf.seek(0, 2)

		if self.start >= buf_len:
			raise JagErrCode(
				f'The requested byterange start {self.start} '
				f'exceeds the target buffer len {buf_len}',
				code=416,
			)

		start = self.start
		if self.end == None:
			end = min(
				(start + cap) - 1,
				buf_len - 1,
			)
		else:
			end = self.end

		reply.headers['content-range'] = (
			f'bytes {start}-{end}/{buf_len}'
		)

		reply.rsp_code = 206

		reply.stream_buf(buf,
			content_type=content_type,
			chunk_size=chunk_size,

			offs=(start, end + 1),

			pass_through=pass_through,
		)



class JagReply(NamedPrint):
	def __init__(self,
		skt_raw,
		headers=None,
	):
		self.skt_raw = skt_raw
		self.headers = headers or JagHeaders.from_blank()

		if not 'server' in self.headers:
			self.headers['server'] = 'JagWrench'

		self.pwrite_locked = False
		self.hwrite_locked = False

		self._rsp_code = 200

	@property
	def rsp_code(self):
		return self._rsp_code

	@rsp_code.setter
	def rsp_code(self, code):
		code = int(code)
		if not code in RSP_CODE_MAP:
			raise ValueError(
				f'Invalid response code: {code}'
			)

		self._rsp_code = code

	@staticmethod
	def lock_pwrite(method):
		def wrap(self, *args, **kwargs):
			if self.pwrite_locked:
				raise TypeError(
					f"""The payload has already been written, """
					f"""but '{method.__name__}' requires write."""
				)

			result = method(self, *args, **kwargs)

			self.pwrite_locked = True

			return result

		return wrap

	@staticmethod
	def lock_hwrite(method):
		def wrap(self, *args, **kwargs):
			if self.hwrite_locked:
				raise TypeError(
					f"""The headers have already been written, """
					f"""but '{method.__name__}' requires write."""
				)

			result = method(self, *args, **kwargs)

			self.hwrite_locked = True

			return result

		return wrap

	@lock_hwrite
	def send_headers(self):
		self.skt_raw.sendall(''.join((
			'HTTP/1.1', ' ',
			RSP_CODE_MAP.get(self.rsp_code, '200 OK'),
			RN_STR,
		)).encode())
		self.headers.send_to(self.skt_raw)
		self.nprint('SENDING HEADERS:')
		print(self.headers.to_printable())
		self.skt_raw.sendall(RN_BYTES)

	@lock_pwrite
	def send_bytes(self, data, content_type=None):
		self.headers['content-length'] = len(data)

		if content_type:
			self.headers['content-type'] = content_type

		if not self.headers['content-type']:
			self.headers['content-type'] = 'application/octet-stream'

		self.send_headers()
		self.skt_raw.sendall(data)

	@lock_pwrite
	def stream_chunks(self, content_type=None):
		self.headers['transfer-encoding'] = 'Chunked'

		if content_type:
			self.headers['content-type'] = content_type

		if not self.headers['content-type']:
			self.headers['content-type'] = 'application/octet-stream'

		self.send_headers()
		return ChunkedStream(self.skt_raw)

	@lock_pwrite
	def stream_buf(self,
		buf,
		content_type=None,
		chunk_size=1024**2,

		offs=(None, None),

		pass_through=None,

		omit_content_length=False,
	):
		offs_start, offs_end = offs

		offs_start = offs_start if (offs_start != None) else 0
		offs_end =   offs_end   if (offs_end != None)   else buf.seek(0, 2)

		self.nprintf('Buf Range:', offs_start, offs_end)

		payload_len = offs_end - offs_start

		if not omit_content_length:
			self.headers['content-length'] = payload_len

		if content_type:
			self.headers['content-type'] = content_type

		if not self.headers['content-type']:
			self.headers['content-type'] = 'application/octet-stream'

		self.send_headers()

		buf.seek(offs_start, 0)

		prog = 0
		pos = buf.tell()
		while (chunk := buf.read(min(payload_len - prog, chunk_size))):
			if pass_through:
				chunk = pass_through(
					pos,
					chunk,
				)

				pos = buf.tell()

			self.skt_raw.sendall(chunk)
			prog += len(chunk)



class JagRequest(NamedPrint):
	def __init__(self,
		skt_rfile,

		query,
		headers,

		envdata=None,
		session=None,
	):
		self.skt_rfile = skt_rfile

		self.query = query
		self.headers = headers

		self._envdata = envdata
		self._sesdata = None
		self.session = session

		self.read_locked = False

		self._byterange = NULL
		self._cookies = None

	@property
	def envdata(self):
		if self.session:
			return self.session.envdata
		else:
			return self._envdata

	@envdata.setter
	def envdata(self, data):
		if self.session:
			self.session.envdata = data
		else:
			self._envdata = data


	@property
	def sesdata(self):
		if self.session:
			return self.session.sesdata
		else:
			return self._sesdata

	@sesdata.setter
	def sesdata(self, data):
		if self.session:
			self.session.sesdata = data
		else:
			self._sesdata = data


	@property
	def byterange(self):
		if self._byterange != NULL:
			return self._byterange

		self._byterange = ByteRange.from_req(self)

		return self._byterange

	@property
	def cookies(self):
		if self._cookies != None:
			return self._cookies

		self._cookies = {}

		for item in (self.headers['cookie'] or '').split(';'):
			item = item.strip()

			if not item:
				continue

			name, sep, value = item.partition('=')

			if sep:
				self._cookies[name.strip()] = value.strip()

		return self._cookies


	@staticmethod
	def lock_read(method):
		def wrap(self, *args, **kwargs):
			if self.read_locked:
				raise TypeError(
					f"""The payload has already been read, """
					f"""but '{method.__name__}' requires read."""
				)

			result = method(self, *args, **kwargs)

			self.read_locked = True

			return result

		return wrap

	def to_printable(self):
		return '\n'.join(frame_lines((
			*self.query.to_printable(),
			*self.headers.to_printable(True)
		)))

	@lock_read
	def read_body_stream(self):
		content_len = None
		chunked = False

		try:
			content_len = int(self.headers['content-length'])
		except:
			pass

		try:
			chunked = 'chunked' in (self.headers['transfer-encoding'] or '').lower()
		except:
			pass

		# Either Content-Length or Transfer-Encoding has to be present
		if (content_len == None) and not chunked:
			raise JagErrCode(
				'No read hints',
				code=411
			)

		# Content-Length and Transfer-Encoding cannot both be present
		if (content_len != None) and chunked:
			raise JagErrCode(
				'Both Content-Length and Transfer-Encoding headers are present',
				code=400,
			)

		"""
		# Content-Length cannot exceed max_len
		if (content_len != None) and (content_len > max_len):
			raise JagErrCode(
				f'Payload of length {content_len} exceeds the limit of {max_len}',
				code=413
			)
		"""

		if content_len != None:
			reader = BasicBodyReader(self.skt_rfile, content_len)

		if chunked:
			reader = ChunkedBodyReader(self.skt_rfile)

		return reader

	@lock_read
	def read_body_full(self, max_len=1024**2, chunk_size=8192):
		buf = bytearray()

		data_stream = self.read_body_stream()
		while (data_chunk := data_stream.read(chunk_size)):
			if len(buf) >= max_len:
				raise JagErrCode(
					f'Payload of length {content_len} '
					f'exceeds the limit of {max_len}.',
					code=413
				)

			buf.extend(data_chunk)

		return bytes(buf)



class JagSession(NamedPrint):
	DEFAULT_MAX_REQUESTS = 100
	DEFAULT_LIFE_DUR_S = 85.000

	# The client has this many seconds to finish sending headers
	# before the socket is force terminated
	DEFAULT_RECV_HEADERS_TIMEOUT_S = 10.000

	# Whether to dump error traceback to clients when a fatal error occurs
	DEFAULT_SHOW_ERR_TRACEBACK = True

	def __init__(self,
		skt_raw,
		callback,

		envdata=None,
		max_requests=None,
		life_dur_s=None,
		recv_headers_timeout_s=None,

		hbuf_size_limit=None,
		query_size_limit=None,

		show_err_traceback=None,

		add_headers=None,

		better_timer=None,
	):
		self.skt_raw = skt_raw
		self.callback = callback
		self.better_timer = better_timer

		self.envdata = envdata
		self.sesdata = None
		self.add_headers = add_headers

		self.max_requests =           max_requests           or self.DEFAULT_MAX_REQUESTS
		self.life_dur_s =             life_dur_s             or self.DEFAULT_LIFE_DUR_S
		self.recv_headers_timeout_s = recv_headers_timeout_s or self.DEFAULT_RECV_HEADERS_TIMEOUT_S

		self.query_size_limit = query_size_limit
		self.hbuf_size_limit =  hbuf_size_limit

		self.show_err_traceback = self.DEFAULT_SHOW_ERR_TRACEBACK
		if show_err_traceback in (True, False):
			self.show_err_traceback = show_err_traceback

		self.remaining_requests = self.max_requests

		self._skt_rfile = None

	@property
	def skt_rfile(self):
		if self._skt_rfile:
			return self._skt_rfile

		self._skt_rfile = self.skt_raw.makefile(
			'rb',
			newline=RN_BYTES,
			buffering=0
		)

		return self._skt_rfile

	def skt_timeout(self, timeout):
		return skt_timeout(
			self.skt_raw,
			timeout,
			skt_files= (self._skt_rfile,),
			timer=     self.better_timer,
		)

	def terminate(self):
		return terminate_skt(
			self.skt_raw,
			(self._skt_rfile,)
		)

	def life_remaining(self, start):
		result = max(
			0,
			self.life_dur_s - (time.monotonic() - start),
		)

		self.nprint('Life remaining:', result)

		return result

	def spawn_reply(self):
		reply = JagReply(self.skt_raw)

		for hname, hval in (self.add_headers or {}).items():
			reply.headers[hname] = str(hval)

		return reply

	def send_error(self, code=None, msg=None, err=None):
		try:
			with self.skt_timeout(7.000):
				err_reply = self.spawn_reply()
				err_reply.rsp_code = code or 500
				err_reply.headers['connection'] = 'Close'

				if self.show_err_traceback and err:
					msg = str_exception(err)

				err_reply.send_bytes(
					str(msg or 'FATAL').encode(),
					'text/plain',
				)
		except Exception as e:
			print_exception_framed(e)

	def run(self):
		start_s = time.monotonic()

		while (self.remaining_requests > 0) and self.life_remaining(start_s):
			self.nprint(
				f'Awaiting request. Will serve {self.remaining_requests} more'
			)
			self.remaining_requests -= 1

			with self.skt_timeout(self.life_remaining(start_s)):
				query = JagQuery.from_skt(
					self.skt_rfile,
					size_limit=self.query_size_limit,
				)

			with self.skt_timeout(self.recv_headers_timeout_s):
				headers = JagHeaders.from_skt(
					self.skt_rfile,
					size_limit=self.hbuf_size_limit
				)

			req = JagRequest(
				self.skt_rfile,

				query,
				headers,

				envdata=self.envdata,
				session=self,
			)

			self.nprint('Got Request:')
			# print(req.to_printable())

			reply = self.spawn_reply()

			if self.remaining_requests <= 0:
				self.nprint(
					'Treating last request. Setting connection to close'
				)
				reply.headers['connection'] = 'Close'
			else:
				reply.headers['connection'] = 'Keep-Alive'

			def edit_headers():
				self.nprint(
					'Session expired while a request was being treated'
				)
				reply.headers['connection'] = 'Close'

			timer = threading.Timer(
				self.life_remaining(start_s),
				edit_headers,
			)

			timer.start()

			try:
				yield req, reply
			except Exception as e:
				print_exception_framed(e)

			try:
				self.callback(req, reply)

				if not reply.hwrite_locked:
					raise JagErrCode(
						'The server chose to ignore this request',
						code=500,
					)
			except JagErrCode as err:
				print_exception_framed(err)
				if not reply.hwrite_locked:
					self.send_error(
						code=err.code,
						msg=str(err),
						err=err,
					)
				if err.fatal or reply.hwrite_locked or reply.pwrite_locked:
					break
			except Exception as e:
				print_exception_framed(e)
				if not reply.hwrite_locked:
					self.send_error(
						code=500,
						msg='JAGWRENCH-FATAL',
						err=e,
					)
				break
			finally:
				timer.cancel()


		self.terminate()

		self.nprint('Exited')

	def run_auto(self):
		for _ in self.run():
			continue




class MPSocketAcceptorThreadPool(NamedPrint):
	DEFAULT_THREAD_AMOUNT = 16
	DEFAULT_MAX_SESSIONS =  50

	DEFAULT_MAX_LIFE_S =       67.000
	DEFAULT_FINISH_TIMEOUT_S = 69.000

	def __init__(self,
		callback,

		thread_amount=None,
		max_sessions=None,
		max_life_s=None,
		finish_timeout_s=None,

		session_config=None,
	):
		self.callback = callback

		self.thread_amount =    thread_amount    or self.DEFAULT_THREAD_AMOUNT
		self.max_sessions =     max_sessions     or self.DEFAULT_MAX_SESSIONS
		self.max_life_s =       max_life_s       or self.DEFAULT_MAX_LIFE_S
		self.finish_timeout_s = finish_timeout_s or self.DEFAULT_FINISH_TIMEOUT_S

		self.session_config = session_config

		self.pipe = None
		self.proc = None

		self.termination_lock = threading.Lock()

	@classmethod
	def run_pool(cls,
		pipe,
		callback,
		thread_amount,
		session_config=None,
	):
		try:
			thread_pool = ThreadPoolExecutor(max_workers=thread_amount)

			while True:
				cl_con = self.pipe.recv()
				cls.nprintc('Got socket:', cl_con)

				if not cl_con:
					cls.nprint('Received collapse signal:', cl_con)
					thread_pool.shutdown(wait=True)
					break

				thread_pool.submit(
					JagSession(
						cl_con,
						self.callback,
						**dict(self.session_config),
					)
					.run_auto
				)

				pipe.send(True)

		except Exception as e:
			cls.nprint('FATAL:', e)
			print_exception_framed(e)
		finally:
			sys.exit()




class MPSocketAcceptor(NamedPrint):
	DEFAULT_POOL_COUNT =         3

	def __init__(self,
		skt_data,
		callback,

		pool_count=None,
		pool_max_life_s=None,
		pool_finish_timeout_s=None,

		session_config=None,
	):
		if not skt_data:
			raise ValueError(
				f'FATAL: invalid skt_data ({skt_data})'
			)

		if isinstance(skt_data, int) and not REUSEPORT_AVAILABLE:
			raise ValueError(
				f'FATAL: skt_data seems to be a port, but socket.SO_REUSEPORT '
				'is NOT available'
			)

		self.skt_data = skt_data
		self.callback = callback

		self.pool_count =         pool_count         or self.DEFAULT_POOL_COUNT

		self.pool_max_life_s =       pool_max_life_s
		self.pool_finish_timeout_s = pool_finish_timeout_s

		self.session_config = tuple(
			(session_config or {}).items()
		)

		self.pool_array = []

		self._listen_skt = None

	@classmethod
	def mp_spawn(cls, *args, **kwargs):
		cls(*args, **kwargs).run()

	@property
	def listen_skt(self):
		if self._listen_skt != None:
			return self._listen_skt

		if isinstance(self.skt_data, int) and REUSEPORT_AVAILABLE:
			self.nprint('REUSEPORT')
			self._listen_skt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

			self._listen_skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			self._listen_skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)

			self._listen_skt.bind(
				('', self.skt_data)
			)

			self._listen_skt.listen(4096)
		else:
			self.nprint('SOCKET AS IS')
			self._listen_skt = self.skt_data

		return self._listen_skt



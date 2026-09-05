import socket
import pickle
import os
import io
import contextlib
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import cryptography.exceptions as crypto_exceptions


from .jag.jag_util import (
	print_exception_framed,
	aligned_recv,
	NamedPrint,
	skt_timeout,
	FasterTimerSched,
	terminate_skt,
)

from .pyspm_exceptions import *





# ==============================
#            UTIL
# ==============================

def bytes_to_bools(data):
	return tuple(
		(byte >> bit) & 1 == 1
		for byte in data
		for bit in range(7, -1, -1)
	)

def bools_to_bytes(data):
	return bytes(
		sum(bit << (7 - i) for i, bit in enumerate(data[offset:offset + 8]))
		for offset in range(0, len(data), 8)
	)



class FuckedUnpicklerButtplug(NamedPrint):
	def __init__(self, *args, **kwargs):
		self.__dict__.update(kwargs)

	def __call__(self, *args, **kwargs):
		return self

	def __repr__(self):
		return '<missing pickle global>'


class FuckedUnpickler(pickle.Unpickler, NamedPrint):
	PRINT_WARNINGS = False

	def find_class(self, module, name):
		try:
			return super().find_class(module, name)
		except (ModuleNotFoundError, AttributeError):
			if self.PRINT_WARNINGS:
				self.nprint('WARNING: MISSING SHIT:', module, name)
			return FuckedUnpicklerButtplug


class BootlegChallenge:
	DEFAULT_DIFFICULTY = 4

	@staticmethod
	def create():
		return secrets.token_hex(32)

	def solve(challenge):
		solution = 0

		target = '0' * self.DEFAULT_DIFFICULTY

		while True:
			data = f'{challenge}{solution}'.encode()
			digest = hashlib.sha256(data).hexdigest()

			if digest.startswith(target):
				return solution

			solution += 1

	def verify(challenge, solution):
		data = f'{challenge}{solution}'.encode()
		digest = hashlib.sha256(data).hexdigest()
		return digest.startswith('0' * self.DEFAULT_DIFFICULTY)






# ==============================
#            STUFF
# ==============================

class PSPMShared(NamedPrint):
	NPRINT_DISABLED = True

	# So basically, it can happen so that the unpickler tries
	# importing a non-existing module...
	# This makes it stfu in a fucked up way
	USE_FUCKED_UNPICKLER = True

	# The OTHER side has this many seconds
	# to read the payload sent by THIS side
	# before its connection is terminated
	DEFAULT_CHUNK_SEND_TIMEOUT = 69.000
	DEFAULT_MSG_SEND_TIMEOUT =   DEFAULT_CHUNK_SEND_TIMEOUT * 2

	# The OTHER side has this many seconds
	# to finish sending the payload
	# before its connection is force terminated
	DEFAULT_CHUNK_RECV_TIMEOUT = 67.000
	DEFAULT_MSG_RECV_TIMEOUT =   DEFAULT_CHUNK_RECV_TIMEOUT * 2

	# The OTHER side has this many seconds
	# to read the ping sent by THIS side
	# before its connection is force terminated
	DEFAULT_PING_TIMEOUT = 6.9

	# Auth is just a regular message, which consists of random bytes.
	AUTH_MSG_LEN = 512

	# Thou who connects has this many seconds
	# to send the first message before their connection is force terminated.
	AUTH_TIMEOUT_S = 5.000

	# Flags:
	# 0 - = Is ping
	# 1 0 = Is last
	# 2 1 = Is pickled
	# 3 2 = Bootleg cipher
	# 5 3 = -
	# 6 4 = -
	# 7 5 = -

	def __init__(self, skt_raw, key, alt_timer=None):
		# The raw socket object
		self.skt_raw = skt_raw
		# 32 bytes-long encryption key
		self.key = bytes(key)
		# Replacement for threading.Timer
		self.alt_timer = alt_timer
		# Encryption object TM
		self.cipher = ChaCha20Poly1305(self.key)
		# Whether a stream is under way
		self.streaming = False


	def skt_timeout(self, timeout):
		return skt_timeout(
			self.skt_raw,
			timeout,
			timer=self.alt_timer,
		)

	def terminate(self):
		terminate_skt(
			self.skt_raw
		)



	def send_ping(self, timeout=None):
		try:
			with self.skt_timeout(timeout or self.DEFAULT_PING_TIMEOUT):
				self.send_chunk(
					os.urandom(32),
					is_last=True,
					is_ping=True,
				)

			return (True, None)
		except Exception as e:
			return (False, e)

	def send_chunk(self, msg_data, is_last=False, timeout=None, is_ping=False):
		do_pickle = not isinstance(msg_data, bytes)
		nonce = os.urandom(12)
		main_payload = self.cipher.encrypt(
			nonce,
			pickle.dumps(msg_data) if do_pickle else msg_data,
			None
		)

		with self.skt_timeout(timeout or self.DEFAULT_CHUNK_SEND_TIMEOUT):
			# Flags
			self.skt_raw.sendall(
				bools_to_bytes((
					# Whether it's a ping
					is_ping,
					# Whether it's the last message in the sequence
					is_last,
					# Whether the payload is pickled
					do_pickle,
				))
			)

			# The size of the pickled shit
			self.skt_raw.sendall(
				len(main_payload).to_bytes(4, 'little')
			)

			# Some mandatory cryptographic shit
			self.skt_raw.sendall(nonce)

			# The pickled shit itself
			self.skt_raw.sendall(main_payload)

	@contextlib.contextmanager
	def send_stream(self, timeout=None):
		self.streaming = True

		def send(chunk_bytes):
			self.send_chunk(
				chunk_bytes,
				is_last=False,
				timeout=timeout,
			)

		try:
			yield send
		finally:
			self.streaming = False
			self.send_chunk(b'', is_last=True, timeout=timeout)

	def send_buf(self, src_buf, timeout=None, chunk_size=(1024**2)*8):
		with self.send_stream(timeout=timeout) as send_fnc:
			while (chunk := src_buf.read(chunk_size)):
				send_fnc(chunk)

	def send_msg(self, msg_data, timeout=None):
		if self.streaming:
			raise ValueError('Finish streaming first')

		self.send_chunk(
			msg_data,
			is_last=True,
			timeout=timeout or self.DEFAULT_MSG_SEND_TIMEOUT,
		)



	def read_header(self):
		while True:
			# Read flags
			msg_flags = bytes_to_bools(
				aligned_recv(self.skt_raw, 1)
			)

			# Unpack flags
			is_ping, _, is_pickled, *_ = msg_flags

			# Read the size of the payload
			payload_len = int.from_bytes(
				aligned_recv(self.skt_raw, 4),
				'little'
			)

			if is_ping:
				self.read_body(payload_len, is_pickled)
				continue
			else:
				break

		return (
			msg_flags[1:],
			payload_len
		)

	def read_body(self, payload_len, is_pickled, timeout=None):
		try:
			with self.skt_timeout(timeout or self.DEFAULT_CHUNK_RECV_TIMEOUT):
				payload_bytes = self.cipher.decrypt(
					# nonce
					aligned_recv(self.skt_raw, 12),

					# pickle bytes
					aligned_recv(self.skt_raw, payload_len),

					# Whatever
					None
				)

			if is_pickled:
				self.nprint('Unpickling')
				return (
					# Eval pickle bytes into python object and return it
					FuckedUnpickler(io.BytesIO(payload_bytes)).load()
					if self.USE_FUCKED_UNPICKLER else
					pickle.loads(payload_bytes)
				)
			else:
				self.nprint('NOT unpickling')
				return payload_bytes

		except crypto_exceptions.InvalidTag as e:
			raise CipherFailure(e)

	def read_chunk(self, timeout=None):
		msg_flags, payload_len = self.read_header()
		_, is_pickled, *_ = msg_flags

		return (
			msg_flags,
			self.read_body(payload_len, is_pickled, timeout=timeout)
		)

	def read_stream(self, timeout=None):
		while True:
			msg_flags, msg_bytes = self.read_chunk(timeout=timeout)
			is_last, *_ = msg_flags

			yield msg_bytes

			if is_last:
				break

	def read_into(self, tgt_buf, timeout=None):
		for chunk in self.read_stream():
			tgt_buf.write(chunk)

	def read_msg(self, timeout=None):
		msg_flags, payload_len = self.read_header()
		is_last, is_pickled, *_ = msg_flags

		if is_last:
			return self.read_body(
				payload_len,
				is_pickled,
				timeout=timeout or self.DEFAULT_MSG_RECV_TIMEOUT
			)

		with self.skt_timeout(timeout or self.DEFAULT_MSG_RECV_TIMEOUT):
			buf = io.BytesIO(
				self.read_body(
					payload_len,
					is_pickled,
					timeout=1337_69
				)
			)

			while True:
				msg_flags, msg_bytes = self.read_chunk(timeout=1337_69)
				is_last, *_ = msg_flags

				buf.write(msg_bytes)

				if is_last:
					break

		return buf.getvalue()



class PSPMListener(NamedPrint):
	NPRINT_DISABLED = True

	def __init__(self, listen_skt, key, alt_timer=None):
		self.listen_skt = listen_skt
		self.key = key
		self.alt_timer = alt_timer

	def __enter__(self):
		return self

	def __exit__(self, e_type, e_val, e_trace):
		self.terminate()

	def terminate(self):
		terminate_skt(self.listen_skt)

	def accept(self):
		# INCOMING socket connection from OTHER side
		skt_con, skt_addr = self.listen_skt.accept()
		self.nprint('Got connection from:', skt_addr)

		# The pspm connection itself
		pspm_con = PSPMConnection(
			skt_con,
			self.key,
			self.alt_timer
		)

		# The first message in the session is just a bunch of random bytes
		# to see whether decryption errors or not.
		# (acts as bootleg auth)
		try:
			msg_data = pspm_con.read_msg(PSPMShared.AUTH_TIMEOUT_S)
		except CipherFailure as e:
			terminate_skt(skt_con)
			raise InvalidKey('Decryption failed')
		except Exception as e:
			terminate_skt(skt_con)
			raise AuthFail(e)

		# Auth message has to be of specific length
		if len(msg_data) != PSPMShared.AUTH_MSG_LEN:
			terminate_skt(skt_con)
			raise WrongAuthMessageLength(
				f'Wrong auth message length: Need {PSPMShared.AUTH_MSG_LEN}, '
				f'but got {len(msg_data)}'
			)

		return pspm_con



class PSPMConnection(PSPMShared):
	NPRINT_DISABLED = True

	def __enter__(self):
		return self

	def __exit__(self, e_type, e_val, e_trace):
		self.terminate()



class PySecurePickleMessaging(NamedPrint):
	NPRINT_DISABLED = True

	# Use a SUPPOSEDLY more performant version of threading.Timer
	USE_ALT_TIMER = True

	def __init__(self, key):
		self.key = bytes(key)

		self.alt_timers_sched = (
			FasterTimerSched() if self.USE_ALT_TIMER else None
		)

		self.alt_timer = (
			self.alt_timers_sched.timer if self.alt_timers_sched else None
		)

	@classmethod
	def generic_socket(cls):
		skt = socket.socket(
			socket.AF_INET,
			socket.SOCK_STREAM
		)

		skt.setsockopt(
			socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
		)

		return skt

	def listener(self, bind_addr, max_clients=69):
		# LISTEN socket, which can give birth to MULTIPLE PSPM sessions
		listen_skt = self.generic_socket()
		listen_skt.bind(bind_addr)
		listen_skt.listen(max_clients)

		return PSPMListener(
			listen_skt,
			self.key,
			alt_timer=self.alt_timer
		)

	def sender(self, tgt_addr):
		# OUTCOMING connection to OTHER side
		listen_skt = self.generic_socket()
		listen_skt.connect(tgt_addr)

		# The pspm connection itself
		pspm_con = PSPMConnection(
			listen_skt,
			self.key,
			alt_timer=self.alt_timer
		)

		# The first message in the session is just a bunch of random bytes
		# to see whether decryption errors or not.
		# (acts as bootleg auth)
		pspm_con.send_msg(
			os.urandom(PSPMShared.AUTH_MSG_LEN)
		)

		# If auth failed - the connection should be closed by now
		ping_ok, ping_error = pspm_con.send_ping()

		if not ping_ok:
			raise AuthFail(ping_error)

		return pspm_con







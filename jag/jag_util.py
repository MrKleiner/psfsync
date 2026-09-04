import traceback
import inspect
import io
import contextlib
import threading
import heapq
import itertools
import time


RECV_BUF_FLOOR = 512




def str_exception(err):
	try:
		return ''.join(
			traceback.format_exception(
				type(err),
				err,
				err.__traceback__
			)
		)
	except Exception as e:
		print(e)
		raise e


def print_exception(err):
	try:
		print(
			''.join(
				traceback.format_exception(
					type(err),
					err,
					err.__traceback__
				)
			)
		)
	except Exception as e:
		print(e)
		raise e


def print_exception_framed(err, extra_linebreakes=False):
	try:
		formatted = ''.join(
			traceback.format_exception(
				type(err),
				err,
				err.__traceback__
			)
		)

		exception_lines = []

		for line in formatted.split('\n'):
			for chunk in [line[i:i+120] for i in range(0, len(line), 120)]:
				exception_lines.append(chunk)

		max_len = 0
		for idx, line in enumerate(exception_lines):
			if len(line) > max_len:
				max_len = len(line)

		print_lines = [
			'+' + ('-' * (max_len + 3 + 4 - 2)) + '+',
		]

		for idx, line in enumerate(exception_lines):
			print_lines.append(
				'| ' + line.ljust(max_len + 3) + ' |'
			)

		print_lines.append(
			'+' + ('-' * (max_len + 3 + 4 - 2)) + '+'
		)

		if extra_linebreakes:
			print(
				'\n' + '\n'.join(print_lines) + '\n'
			)
		else:
			print(
				'\n'.join(print_lines)
			)

	except Exception as e:
		print_exception(e)


def frame_lines(line_array):
	pad = 0
	for line in line_array:
		line = str(line)
		if len(line) > pad:
			pad = len(line)

	pad += 5

	return [
		'+' + ('-' * (pad+1)) + '+',
		*map(lambda i: '| ' + str(i).ljust(pad) + '|', line_array),
		'+' + ('-' * (pad+1)) + '+',
	]


def calc_string_pad(line_array, extra=3):
	pad = 0
	for line in line_array:
		line = str(line)
		if len(line) > pad:
			pad = len(line)

	pad += extra

	return pad


def clamp_num(num, tgt_min, tgt_max):
	return max(tgt_min, min(num, tgt_max))


def aligned_recv(skt_con, bufsize, chunk_size=8192):
	# Shouldn't this print a warning or something ?
	if bufsize <= 0:
		return b''

	# Creating an io.BytesIO buffer to receive 2 bytes
	# is MUCH slower than simple concatenating (b'' + ...)
	# Through tests it was determined that there's no need to
	# create a buffer for receiving less than 512 bytes.
	# todo: Lower the number a little bit just to be sure?
	if bufsize < RECV_BUF_FLOOR:
		buf = b''
		# print('Need to receive:', bufsize)
		while True:
			# todo: raise a warning when the result is actually longer
			# than anticipated
			if len(buf) >= bufsize:
				return buf

			data = skt_con.recv(
				clamp_num(chunk_size, 1, bufsize - len(buf))
			)

			if not data:
				raise ConnectionError('Connection closed')

			buf += data
	else:
		buf = io.BytesIO()
		while True:
			if buf.tell() >= bufsize:
				return buf.getvalue()

			data = skt_con.recv(
				clamp_num(chunk_size, 1, bufsize - buf.tell())
			)

			if not data:
				raise ConnectionError('Connection closed')

			buf.write(data)

		buf = buf.getvalue()

	return buf


def terminate_skt(skt, skt_files=None):
	for f in (skt_files or ()):
		try:
			f.flush()
		except:
			pass

		try:
			f.close()
		except:
			pass

	try:
		skt.shutdown(socket.SHUT_RDWR)
	except:
		pass

	try:
		skt.close()
	except:
		pass


@contextlib.contextmanager
def skt_timeout(skt, timeout, skt_files=None, timer=None):
	if timeout <= 0:
		terminate_skt(skt, skt_files)
		yield skt
		return

	th_timer = (timer or threading.Timer)(
		timeout,
		terminate_skt,
		args=(skt, skt_files)
	)

	try:
		th_timer.start()
		yield skt
	finally:
		th_timer.cancel()









class ClassDict:
	def __init__(self, **kwargs):
		for key, val in kwargs.items():
			setattr(self, key, val)



class NPrintData:
	SMART_ALIGN = True

	LONGEST = 30

	EXTRA_PAD = 3

	@classmethod
	def apply(cls, tgt_str):
		if cls.SMART_ALIGN:
			if len(tgt_str) >= cls.LONGEST:
				cls.LONGEST = len(tgt_str) + cls.EXTRA_PAD

			return tgt_str.ljust(cls.LONGEST)

		return tgt_str



class NamedPrint:
	NPRINT_DISABLED = False

	# Class name
	@classmethod
	def nprint(cls, *args, **kwargs):
		if not cls.NPRINT_DISABLED:
			print(
				f'[{NPrintData.apply(cls.__name__)}]',
				*args,
				**kwargs,
			)

	# Class name + function name
	@classmethod
	def nprintf(cls, *args, **kwargs):
		if not cls.NPRINT_DISABLED:
			print(
				'.'.join((
					f'[{NPrintData.apply(cls.__name__)}]',
					str(inspect.stack()[1].function),
				)),
				*args,
				**kwargs,
			)

	# Class name, clamped line width
	@classmethod
	def nprintc(cls, *args, **kwargs):
		if not cls.NPRINT_DISABLED:
			lines = ' '.join(map(str, args)).split('\n')
			if not lines:
				cls.nprint()
				return

			cls.nprint(lines[0][0:100])

			del lines[0]

			for line in lines:
				print(line[0:100])



class FasterTimer:
	def __init__(self, sched, interval, function, args=None, kwargs=None):
		self.sched = sched
		self.interval = interval
		self.function = function
		self.args = args or ()
		self.kwargs = kwargs or {}

		self._cancelled = False
		self._deadline = None

	def start(self):
		self.sched.schedule(self)
		return self

	def cancel(self):
		self.sched.cancel(self)



class FasterTimerSched:
	def __init__(self):
		self._cv = threading.Condition()
		self._heap = []
		self._counter = itertools.count()

		self.thread = threading.Thread(
			target=self.run,
			daemon=True,
			name='FasterTimerSched',
		)

		self.thread.start()

	def schedule(self, timer):
		with self._cv:
			timer._deadline = time.monotonic() + timer.interval
			timer._cancelled = False

			heapq.heappush(
				self._heap,
				(timer._deadline, next(self._counter), timer)
			)

			self._cv.notify()

		return timer

	def timer(self, *args, **kwargs):
		return FasterTimer(
			self,
			*args,
			**kwargs,
		)

	def cancel(self, timer):
		with self._cv:
			timer._cancelled = True
			self._cv.notify()

	def run(self):
		while True:
			with self._cv:
				while not self._heap:
					self._cv.wait()

				while True:
					deadline, _, timer = self._heap[0]
					now = time.monotonic()

					if deadline > now:
						self._cv.wait(deadline - now)

						if not self._heap:
							break

						continue

					heapq.heappop(self._heap)

					if timer._cancelled:
						break

					break

			if not timer._cancelled:
				try:
					timer.function(*timer.args, **timer.kwargs)
				except Exception:
					import traceback
					traceback.print_exc()



class TDict:
	# Thread-safER dictionaries

	def __init__(self):
		self.real_dict = {}
		self.th_lock = threading.Lock()

	@contextlib.contextmanager
	def edit(self):
		with self.th_lock:
			yield self.real_dict

	def __getitem__(self, key):
		with self.th_lock:
			return self.real_dict.get(key)

	def __setitem__(self, key, val):
		with self.th_lock:
			self.real_dict[key] = val

	def __delitem__(self, key):
		with self.th_lock:
			if key in self.real_dict:
				del self.real_dict[key]

	def __contains__(self, key):
		with self.th_lock:
			return (
				key in self.real_dict
			)



import contextlib
import threading
import time
import shutil
import argparse
import queue
from fnmatch import fnmatch

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

from watchdog.observers import Observer as WatchdogObserver
from watchdog.events import FileSystemEventHandler


from pspm.pyspm import PySecurePickleMessaging

from jag.jag_util import (
	print_exception_framed,
	NamedPrint,
)



def await_file_ready(
	fpath,
	stable_for_s=1.15,
	check_interval_s=0.1
):
	fpath = Path(fpath)

	last_size = -1
	last_mtime = None
	stable_since = None

	while True:
		if not fpath.is_file():
			return False

		try:
			stat = fpath.stat()
		except FileNotFoundError:
			time.sleep(check_interval_s)
			continue

		size = stat.st_size
		mtime = stat.st_mtime_ns

		if size == last_size and mtime == last_mtime:
			if stable_since is None:
				stable_since = time.monotonic()
			elif time.monotonic() - stable_since >= stable_for_s:
				return True
		else:
			last_size = size
			last_mtime = mtime
			stable_since = None

		time.sleep(check_interval_s)



class PSFSyncFileMessage(NamedPrint):
	DEBUG_NO_ACTION = False

	def __init__(self, rel_path, action):
		self.psfsync_con = None

		self.rel_path = rel_path
		self.action = action
		self.fpath_type = None

	def __call__(self, psfsync_con):
		self.psfsync_con = psfsync_con

	@property
	def abspath(self):
		return self.psfsync_con.root_dir / self.rel_path

	@property
	def abspath_valid(self):
		return self.abspath.is_relative_to(
			self.psfsync_con.root_dir
		)

	def read(self):
		if not self.abspath_valid:
			self.nprint('FATAL: Invalid path', self.abspath)
			raise ValueError(f'Invalid path:', self.abspath)

		# Type is determined automatically when deleting
		if self.action == 'delete':
			if self.abspath.is_dir():
				self.nprint('DIR  DEL  :', self.abspath)
				if not self.DEBUG_NO_ACTION:
					shutil.rmtree(self.abspath, ignore_errors=True)
			else:
				self.nprint('FILE DEL  :', self.abspath)
				if not self.DEBUG_NO_ACTION:
					self.abspath.unlink(missing_ok=True)
			return

		if self.fpath_type == 'dir':
			# Directories are "created" by "writing"
			if self.action in ('create', 'write', 'touch'):
				self.nprint('DIR CREATE:', self.abspath)
				if not self.DEBUG_NO_ACTION:
					self.abspath.mkdir(exist_ok=True)
			return

		if self.fpath_type == 'file':
			if self.action == 'write':
				self.nprint('FILE WRITE:', self.abspath)
				if not self.DEBUG_NO_ACTION:
					self.abspath.unlink(missing_ok=True)
					self.abspath.parent.mkdir(exist_ok=True, parents=True)
					with open(self.abspath, 'wb') as tgt_buf:
						self.psfsync_con.pspm_con.read_into(tgt_buf)
				else:
					self.psfsync_con.pspm_con.read_msg()

			if self.action == 'touch':
				self.nprint('FILE TOUCH:', self.abspath)
				if not self.DEBUG_NO_ACTION:
					self.abspath.parent.mkdir(exist_ok=True, parents=True)
					self.abspath.touch()
			return

	def send(self):
		self.fpath_type = 'file' if self.abspath.is_file() else 'dir'

		# Header is always present
		self.psfsync_con.pspm_con.send_msg(self)

		# Delete operation never have anything apart from header
		if self.action == 'delete':
			return 

		# All files must have contents
		if self.fpath_type == 'file':
			if self.action == 'write':
				for _ in range(3):
					try:
						with open(self.abspath, 'rb') as src_buf:
							src_buf.read(3)
						break
					except:
						time.sleep(0.1)
				else:
					return self.psfsync_con.pspm_con.send_msg(b'')

				with open(self.abspath, 'rb') as src_buf:
					self.psfsync_con.pspm_con.send_buf(src_buf)



class WatchdogEventHandler(FileSystemEventHandler, NamedPrint):
	def __init__(self, task_sched, *args, **kwargs):
		super().__init__(*args, **kwargs)
		self.task_sched = task_sched

	def on_created(self, event):
		self.nprint('TOUCH  :', event.src_path)

		self.task_sched.put(
			(event.src_path, 'touch')
		)

	def on_modified(self, event):
		self.nprint('MOD    :', event.src_path)

		self.task_sched.put(
			(event.src_path, 'write')
		)

	def on_deleted(self, event):
		self.nprint('DEL    :', event.src_path)

		self.task_sched.put(
			(event.src_path, 'delete')
		)

	def on_moved(self, event):
		self.nprint('MOVE   :', event.src_path, '->', event.dest_path)

		# Delete old
		self.task_sched.put(
			(event.src_path, 'delete')
		)

		# Write new
		self.task_sched.put(
			(event.dest_path, 'write')
		)



class PSFSyncConnection(NamedPrint):
	def __getstate__(self):
		return None



class PSFSyncSender(PSFSyncConnection):
	DEFAULT_DO_PING = True
	DEFAULT_PING_INTERVAL_S = 3

	def __init__(self,
		pspm_con,
		local_dir,
		remote_dir,
		ignore=None,
		immediate_tasks=None,
	):
		self.pspm_con = pspm_con
		self.root_dir = Path(local_dir)
		self.remote_dir = remote_dir

		self.task_sched = queue.Queue()
		self.observer = None

		# Ignore patterns
		self.ignore = tuple(ignore or ())

		# Schedule any immediate operations
		for task in (immediate_tasks or ()):
			self.task_sched.put(task)

	def create_observer(self):
		if self.observer:
			self.nprint('Observer already exists')
			return

		# Create filesystem observer
		self.observer = WatchdogObserver()
		self.observer.schedule(
			WatchdogEventHandler(self.task_sched),
			str(self.root_dir),
			recursive=True,
		)

		# Run the observer
		self.observer.start()

	def run(self):
		# First message is the remote root dir
		self.pspm_con.send_msg(
			str(self.remote_dir)
		)

		# Create file observer
		self.create_observer()

		# Send messages
		while True:
			try:
				abs_path, action = self.task_sched.get(
					timeout=self.DEFAULT_PING_INTERVAL_S
				)
			except queue.Empty:
				if self.DEFAULT_DO_PING:
					ping_ok, ping_error = self.pspm_con.send_ping(timeout=5)

					if ping_error:
						raise ping_error

					if not ping_ok:
						return

				continue

			rel_path = (
				Path(abs_path)
				.relative_to(self.root_dir)
				.as_posix()
				.strip('/')
			)

			# Check for ignored items
			for pattern in self.ignore:
				if fnmatch('/' + rel_path, pattern):
					break
			else:
				# Create
				cmd = PSFSyncFileMessage(rel_path, action)

				# Set ownership to sender
				cmd(self)

				# Send
				cmd.send()

		self.observer.join()



class PSFSyncReader(PSFSyncConnection):
	def __init__(self, pspm_con):
		self.pspm_con = pspm_con
		# Reader is a sender's bitch
		self.root_dir = None

	def run(self):
		try:
			# First message from the sender dictates the root dir.
			# The fact there's first message also means
			# that the connection is immediately "pinged"
			self.root_dir = Path(self.pspm_con.read_msg())
			self.nprint('Declared root dir:', self.root_dir)

			while True:
					# Receive command
					cmd = self.pspm_con.read_msg()
					# Set ownership to reader
					cmd(self)
					# Exec the command
					cmd.read()

					cmd.nprint('DONE')
		except Exception as e:
			print_exception_framed(e)
			raise e



class PSFSyncServer(NamedPrint):
	def __init__(self, pspm_server):
		self.pspm_server = pspm_server
		self.thread_pool = ThreadPoolExecutor(max_workers=32)

	def run(self):
		while True:
			try:
				self.nprint('Awaiting connections...')

				# Create pspm session
				pspm_con = self.pspm_server.accept()
				self.nprint('Accepted connection from:', pspm_con.skt_raw)

				# Create the client and make it read incoming messages
				self.thread_pool.submit(
					PSFSyncReader(pspm_con).run
				)
			except Exception as e:
				print_exception_framed(e)
				time.sleep(0.75)



class PythonSimpleFileSync(NamedPrint):
	def __init__(self, key):
		self.key = key

	@contextlib.contextmanager
	def server(self, bind_addr):
		with PySecurePickleMessaging(self.key).listener(bind_addr) as pspm_server:
			yield PSFSyncServer(
				pspm_server,
			)

	@contextlib.contextmanager
	def sender(self, tgt_addr, *args, **kwargs):
		with PySecurePickleMessaging(self.key).sender(tgt_addr) as pspm_con:
			ping_ok, ping_error = pspm_con.ping(timeout=6)
			if not ping_ok or ping_error:
				raise Exception(
					f'PSFS post-connection ping failed: {ping_error}. '
					'Wrong key is the most likely issue'
				)

			yield PSFSyncSender(
				pspm_con,
				*args,
				**kwargs,
			)








def main():
	print('Python Simple File Sync initializing...')

	args = argparse.ArgumentParser()
	args.add_argument('-type')
	args.add_argument('-addr')
	args.add_argument('-local_root_dir')
	args.add_argument('-remote_root_dir')
	args.add_argument('-key')
	args.add_argument('-immediate_sync')
	args.add_argument('-ignore')
	args = args.parse_args()

	psfsync = PythonSimpleFileSync(args.key.encode())
	ip, port = args.addr.split(':')
	addr = (ip, int(port))


	if args.type == 'server':
		with psfsync.server(addr) as psfsync_server:
			print('Running server on', addr)
			psfsync_server.run()

	if args.type == 'client':
		immediate_tasks = []
		if args.immediate_sync == '1':
			path_array = tuple(
				i for i in Path(args.local_root_dir).rglob('*')
			)

			# Schedule deletion
			immediate_tasks.extend(
				((p, 'delete') for p in path_array) 
			)

			# Schedule write
			immediate_tasks.extend(
				((p, 'write') for p in path_array) 
			)

		ignore = []
		if args.ignore:
			for line in Path(args.ignore).read_text().split('\n'):
				line = line.strip()
				if not line or line.startswith('#'):
					continue

				ignore.append(line)

		while True:
			try:
				with psfsync.sender(
					addr,
					args.local_root_dir,
					args.remote_root_dir,
					ignore=ignore,
					immediate_tasks=immediate_tasks,
				) as psfsync_client:
					print('Connected to', addr)
					psfsync_client.run()
			except Exception as e:
				print_exception_framed(e)
				time.sleep(0.75)



if __name__ == '__main__':
	main()

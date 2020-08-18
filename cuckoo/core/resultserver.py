# Copyright (C) 2012-2013 Claudio Guarnieri.
# Copyright (C) 2014-2019 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import print_function

import errno
import gevent.pool
import gevent.server
import gevent.socket
import json
import logging
import os
import socket
import threading
import select
import datetime
import SocketServer

from cuckoo.common.abstracts import ProtocolHandler
from cuckoo.common.config import config
from cuckoo.common.exceptions import CuckooCriticalError
from cuckoo.common.exceptions import CuckooOperationalError
from cuckoo.common.exceptions import CuckooResultError
from cuckoo.common.files import Folders
from cuckoo.common.netlog import BsonParser
from cuckoo.common.files import open_exclusive
from cuckoo.common.utils import Singleton
from cuckoo.core.log import task_log_start, task_log_stop
from cuckoo.misc import cwd

log = logging.getLogger(__name__)

#BUFSIZE = 1024*1024

# Maximum line length to read for netlog messages, to avoid memory exhaustion
MAX_NETLOG_LINE = 4 * 1024

# Maximum number of bytes to buffer for a single connection
BUFSIZE = 1024 * 1024

class Disconnect(Exception):
    pass
class ResultServer(SocketServer.ThreadingTCPServer, object):
    __metaclass__ = Singleton
    allow_reuse_address = True
    daemon_threads = True
    def __init__(self, *args, **kwargs):
        self.analysistasks = {}
        self.analysishandlers = {}
        self.ip = config("cuckoo:resultserver:ip")
        self.port = config("cuckoo:resultserver:port")
        while True:
            try: 
                server_addr = self.ip, self.port
                SocketServer.ThreadingTCPServer.__init__(
                    self, server_addr, ResultHandler, *args, **kwargs
                )
            except Exception as e:
                if e.errno == errno.EADDRINUSE:
                    if config("cuckoo:resultserver:force_port"):
                        raise CuckooCriticalError(
                            "Cannot bind ResultServer on port %d, "
                            "bailing." % self.port
                        )
                    else:
                        log.warning("Cannot bind ResultServer on port %s, "
                                    "trying another port.", self.port)
                        self.port += 1
                elif e.errno == errno.EADDRNOTAVAIL:
                    raise CuckooCriticalError(
                        "Unable to bind ResultServer on %s:%s %s. This "
                        "usually happens when you start Cuckoo without "
                        "bringing up the virtual interface associated with "
                        "the ResultServer IP address. Please refer to "
                        "https://cuckoo.sh/docs/faq/#troubles-problem"
                        " for more information." % (self.ip, self.port, e)
                    )
                else:
                    raise CuckooCriticalError(
                        "Unable to bind ResultServer on %s:%s: %s" %
                        (self.ip, self.port, e)
                    )
            else:
                log.debug(
                    "ResultServer running on %s:%s.", self.ip, self.port
                )
                self.servethread = threading.Thread(target=self.serve_forever)
                self.servethread.setDaemon(True)
                self.servethread.start()
                break
# Directories in which analysis-related files will be stored; also acts as
# safelist
RESULT_UPLOADABLE = ("files", "shots", "buffer",  "extracted", "memory")
RESULT_DIRECTORIES = RESULT_UPLOADABLE + ("reports", "logs")

# Prevent malicious clients from using potentially dangerous filenames
# E.g. C API confusion by using null, or using the colon on NTFS (Alternate
# Data Streams); XXX: just replace illegal chars?
BANNED_PATH_CHARS = b'\x00:'

def netlog_sanitize_fname(path):
    """Validate agent-provided path for result files"""
    path = path.replace("\\", "/")
    dir_part, name = os.path.split(path)
    if dir_part not in RESULT_UPLOADABLE:
        raise CuckooOperationalError("Netlog client requested banned path: %r"
                                     % path)
    if any(c in BANNED_PATH_CHARS for c in name):
        for c in BANNED_PATH_CHARS:
            path = path.replace(c, "X")

    return path

class HandlerContext(object):
    """Holds context for protocol handlers.

    Can safely be cancelled from another thread, though in practice this will
    not occur often -- usually the connection between VM and the ResultServer
    will be reset during shutdown."""
    def __init__(self, task_id, storagepath, sock):
        self.task_id = task_id
        self.command = None

        # The path where artifacts will be stored
        self.storagepath = storagepath
        self.sock = sock
        self.buf = ""

    def __repr__(self):
        return "<Context for %s>" % self.command

    def cancel(self):
        """Cancel this context; gevent might complain about this with an
        exception later on."""
        try:
            self.sock.shutdown(socket.SHUT_RD)
        except socket.error:
            pass

    def read(self):
        try:
            return self.sock.recv(16384)
        except socket.error as e:
            if e.errno == errno.EBADF:
                return ""

            if e.errno != errno.ECONNRESET:
                raise
            log.debug("Task #%s had connection reset for %r", self.task_id,
                      self)
            return ""

    def drain_buffer(self):
        """Drain buffer and end buffering"""
        buf, self.buf = self.buf, None
        return buf

    def read_newline(self):
        """Read until the next newline character, but never more than
        `MAX_NETLOG_LINE`."""
        while True:
            pos = self.buf.find("\n")
            if pos < 0:
                if len(self.buf) >= MAX_NETLOG_LINE:
                    raise CuckooOperationalError("Received overly long line")
                buf = self.read()
                if buf == "":
                    raise EOFError
                self.buf += buf
                continue
            line, self.buf = self.buf[:pos], self.buf[pos + 1:]
            return line

    def copy_to_fd(self, fd, max_size=None):
        if max_size:
            fd = WriteLimiter(fd, max_size)
        fd.write(self.drain_buffer())
        while True:
            buf = self.read()
            if buf == "":
                break
            fd.write(buf)
        fd.flush()

class WriteLimiter(object):
    def __init__(self, fd, remain):
        self.fd = fd
        self.remain = remain
        self.warned = False

    def write(self, buf):
        size = len(buf)
        write = min(size, self.remain)
        if write:
            self.fd.write(buf[:write])
            self.remain -= write
        if size and size != write:
            if not self.warned:
                log.warning("Uploaded file length larger than upload_max_size, "
                            "stopping upload.")
                self.fd.write("... (truncated)")
                self.warned = True

    def flush(self):
        self.fd.flush()
    def serve_forever(self, poll_interval=0.5)
        try:
            super(ResultServer, self).serve_forever(poll_interval)
        except AttributeError as e:
            if "NoneType" not in e.message or "select" not in e.message:
                raise

    def add_task(self, task, machine):
        """Register a task/machine with the ResultServer."""
        self.analysistasks[machine.ip] = task, machine
        self.analysishandlers[task.id] = []

    def del_task(self, task, machine):
        """Delete ResultServer state and wait for pending RequestHandlers."""
        x = self.analysistasks.pop(machine.ip, None)
        if not x:
            log.warning("ResultServer did not have %s in its task info.",
                        machine.ip)
        handlers = self.analysishandlers.pop(task.id, None)
        for h in handlers:
            h.end_request.set()
            h.done_event.wait()

    def register_handler(self, handler):
        """Register a RequestHandler so that we can later wait for it."""
        task, machine = self.get_ctx_for_ip(handler.client_address[0])
        if not task or not machine:
            return False

        self.analysishandlers[task.id].append(handler)

    def get_ctx_for_ip(self, ip):
        """Return state for this IP's task."""
        x = self.analysistasks.get(ip)
        if not x:
            log.debug("ResultServer unable to map ip to context: %s.", ip)
            return None, None

        return x

    def build_storage_path(self, ip):
        """Initialize analysis storage folder."""
        task, machine = self.get_ctx_for_ip(ip)
        if not task or not machine:
            return

        return cwd("storage", "analyses", "%s" % task.id)

class ResultHandler(SocketServer.BaseRequestHandler):
    """Result handler.
    This handler speaks our analysis log network protocol.
    """

    def setup(self):
        self.rawlogfd = None
        self.protocol = None
        self.startbuf = ""
        self.end_request = threading.Event()
        self.done_event = threading.Event()
        self.server.register_handler(self)

        if hasattr(select, "poll"):
            self.poll = select.poll()
            self.poll.register(self.request, select.POLLIN)
        else:
            self.poll = None

    def finish(self):
        self.done_event.set()

        if self.protocol:
            self.protocol.close()
        if self.rawlogfd:
            self.rawlogfd.close()

    def wait_sock_or_end(self):
        while True:
            if self.end_request.isSet():
                return False

            if self.poll:
                if self.poll.poll(1000):
                    return True
            else:
                rs, _, _ = select.select([self.request], [], [], 1)
                if rs:
                    return True

    def seek(self, pos):
        pass

    def read(self, length):
        buf = ""
        while len(buf) < length:
            if not self.wait_sock_or_end():
                raise Disconnect()
            tmp = self.request.recv(length-len(buf))
            if not tmp:
                raise Disconnect()
            buf += tmp

        if isinstance(self.protocol, BsonParser):
            if self.rawlogfd:
                self.rawlogfd.write(buf)
            else:
                self.startbuf += buf

                if len(self.startbuf) > 0x10000:
                    raise CuckooResultError(
                        "Somebody is knowingly overflowing the startbuf "
                        "buffer, possibly to use excessive amounts of memory."
                    )

        return buf

    def read_any(self):
        if not self.wait_sock_or_end():
            raise Disconnect()
        tmp = self.request.recv(BUFSIZE)
        if not tmp:
            raise Disconnect()
        return tmp

    def read_newline(self, strip=False):
        buf = ""
        while "\n" not in buf:
            buf += self.read(1)

        if strip:
            buf = buf.strip()

        return buf

    def negotiate_protocol(self):
        protocol = self.read_newline(strip=True)

        # Command with version number.
        if " " in protocol:
            command, version = protocol.split()
            version = int(version)
        else:
            command, version = protocol, None

        if command == "BSON":
            self.protocol = BsonParser(self, version)
        elif command == "FILE":
            self.protocol = FileUpload(self, version)
        elif command == "LOG":
            self.protocol = LogHandler(self, version)
        else:
            raise CuckooOperationalError(
                "Netlog failure, unknown protocol requested."
            )

        self.protocol.init()

    def handle(self):
        ip, port = self.client_address

        self.storagepath = self.server.build_storage_path(ip)
        if not self.storagepath:
            return

        task, _ = self.server.get_ctx_for_ip(ip)
        task_log_start(task.id)

        # Create all missing folders for this analysis.
        self.create_folders()

        try:
            # Initialize the protocol handler class for this connection.
            self.negotiate_protocol()

            for event in self.protocol:
                if isinstance(self.protocol, BsonParser) and event["type"] == "process":
                    self.open_process_log(event)
        except CuckooResultError as e:
            log.warning(
                "ResultServer connection stopping because of "
                "CuckooResultError: %s.", e
            )
        except (Disconnect, socket.error):
            pass
        except:
            log.exception("FIXME - exception in resultserver connection %s",
                          self.client_address)

        task_log_stop(task.id)

    def open_process_log(self, event):
        pid = event["pid"]
        ppid = event["ppid"]
        procname = event["process_name"]

        if self.rawlogfd:
            log.debug(
                "ResultServer got a new process message but already "
                "has pid %d ppid %s procname %s.", pid, ppid, procname
            )
            raise CuckooResultError(
                "ResultServer connection state inconsistent."
            )

        if not isinstance(pid, (int, long)):
            raise CuckooResultError(
                "An invalid process identifier has been provided, this "
                "could be a potential security hazard."
            )

        # Only report this process when we're tracking it.
        if event["track"]:
            log.debug(
                "New process (pid=%s, ppid=%s, name=%s)",
                pid, ppid, procname.encode("utf8")
            )

        filepath = os.path.join(self.storagepath, "logs", "%s.bson" % pid)
        self.rawlogfd = open(filepath, "wb")
        self.rawlogfd.write(self.startbuf)

    def create_folders(self):
        folders = "shots", "files", "logs", "buffer", "extracted"

        try:
            Folders.create(self.storagepath, folders)
        except CuckooOperationalError as e:
            log.error("Issue creating analyses folders: %s", e)
            return False
class FileUpload(ProtocolHandler):
    RESTRICTED_DIRECTORIES = "reports/",
    lock = threading.Lock()
    def init(self):
        self.upload_max_size = config("cuckoo:resultserver:upload_max_size")
        self.storagepath = self.handler.storagepath
        self.fd = None
        self.filelog = os.path.join(self.handler.storagepath, "files.json")
    def __iter__(self):
        dump_path = self.handler.read_newline(strip=True).replace("\\", "/")
            if self.version >= 2:
                filepath = self.handler.read_newline(strip=True)
                pids = map(int, self.handler.read_newline(strip=True).split())
            else:
                filepath, pids = None, []
            log.debug("file upload request for %s", dump_path)
            dir_part, filename = os.path.split(dump_path)
            if "./" in dump_path or not dir_part or dump_path.startswith("/"):
                raise CuckooOperationalError(
                    "FileUpload failure, banned path: %s" % dump_path
                )
    def handle(self):
        # Read until newline for file path, e.g.,
        # shots/0001.jpg or files/9498687557/libcurl-4.dll.bin
        self.handler.sock.settimeout(30)
        dump_path = netlog_sanitize_fname(self.handler.read_newline())

        if self.version and self.version >= 2:
            # NB: filepath is only used as metadata
            filepath = self.handler.read_newline()
            pids = map(int, self.handler.read_newline().split())
        else:
            filepath, pids = None, []

        log.debug("Task #%s: File upload for %r", self.task_id, dump_path)
        file_path = os.path.join(self.storagepath, dump_path.decode("utf-8"))

        try:
            self.fd = open_exclusive(file_path)
        except OSError as e:
            if e.errno == errno.EEXIST:
                raise CuckooOperationalError("Analyzer for task #%s tried to "
                                             "overwrite an existing file" %
                                             self.task_id)
            raise

        # Append-writes are atomic
        with open(self.filelog, "a+b") as f:
            print(json.dumps({
                "path": dump_path,
                "filepath": filepath,
                "pids": pids,
            }), file=f)

        self.handler.sock.settimeout(None)
        try:
            return self.handler.copy_to_fd(self.fd, self.upload_max_size)
        finally:
            log.debug("Task #%s uploaded file length: %s", self.task_id,
                      self.fd.tell())

class LogHandler(ProtocolHandler):
    """The live analysis log. Can only be opened once in a single session."""

    def init(self):
        self.logpath = os.path.join(self.handler.storagepath, "analysis.log")
        try:
            self.fd = open_exclusive(self.logpath, bufsize=1)
        except OSError:
            log.error("Task #%s: attempted to reopen live log analysis.log.",
                      self.task_id)
            return

        log.debug("Task #%s: live log analysis.log initialized.",
                  self.task_id)

    def handle(self):
        if self.fd:
            return self.handler.copy_to_fd(self.fd)

class BsonStore(ProtocolHandler):
    def init(self):
        # We cheat a little bit through the "version" variable, but that's
        # acceptable and backwards compatible (for now). Backwards compatible
        # in the sense that newer Cuckoo Monitor binaries work with older
        # versions of Cuckoo, the other way around doesn't apply here.
        if self.version is None:
            log.warning("Agent is sending BSON files without PID parameter, "
                        "you should probably update it")
            self.fd = None
            return

        self.fd = open(os.path.join(self.handler.storagepath,
                                    "logs", "%d.bson" % self.version), "wb")

    def handle(self):
        """Read a BSON stream, attempting at least basic validation, and
        log failures."""
        log.debug("Task #%s is sending a BSON stream", self.task_id)
        if self.fd:
            return self.handler.copy_to_fd(self.fd)

class GeventResultServerWorker(gevent.server.StreamServer):
    """The new ResultServer, providing a huge performance boost as well as
    implementing a new dropped file storage format avoiding small fd limits.

    The old ResultServer would start a new thread per socket, greatly impacting
    the overall performance of Cuckoo Sandbox. The new ResultServer uses
    so-called Greenlets, low overhead green-threads by Gevent, imposing much
    less kernel overhead.

    Furthermore, instead of writing each dropped file to its own location (in
    $CWD/storage/analyses/<task_id>/files/<partial_hash>_filename.ext) it's
    capable of storing all dropped files in a streamable container format. This
    is one of various steps to start being able to use less fd's in Cuckoo.
    """
    commands = {
        "BSON": BsonStore,
        "FILE": FileUpload,
        "LOG": LogHandler,
    }
    task_mgmt_lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        super(GeventResultServerWorker, self).__init__(*args, **kwargs)

        # Store IP address to task_id mapping
        self.tasks = {}

        # Store running handlers for task_id
        self.handlers = {}

    def do_run(self):
        self.serve_forever()

    def add_task(self, task_id, ipaddr):
        with self.task_mgmt_lock:
            self.tasks[ipaddr] = task_id
            log.debug("Now tracking machine %s for task #%s", ipaddr, task_id)

    def del_task(self, task_id, ipaddr):
        """Delete ResultServer state and abort pending RequestHandlers. Since
        we're about to shutdown the VM, any remaining open connections can
        be considered a bug from the VM side, since all connections should
        have been closed after the analyzer signalled completion."""
        with self.task_mgmt_lock:
            if self.tasks.pop(ipaddr, None) is None:
                log.warning(
                    "ResultServer did not have a task with ID %s and IP %s",
                    task_id, ipaddr
                )
            else:
                log.debug(
                    "Stopped tracking machine %s for task #%s",
                    ipaddr, task_id
                )
            ctxs = self.handlers.pop(task_id, set())
            for ctx in ctxs:
                log.debug("Cancel %s for task %r", ctx, task_id)
                ctx.cancel()

    def handle(self, sock, addr):
        """Handle the incoming connection.
        Gevent will close the socket when the function returns."""
        ipaddr = addr[0]

        with self.task_mgmt_lock:
            task_id = self.tasks.get(ipaddr)
            if not task_id:
                log.warning("ResultServer did not have a task for IP %s",
                            ipaddr)
                return

        storagepath = cwd(analysis=task_id)
        ctx = HandlerContext(task_id, storagepath, sock)
        task_log_start(task_id)
        try:
            try:
                protocol = self.negotiate_protocol(task_id, ctx)
            except EOFError:
                return

            # Registering the context allows us to abort the handler by
            # shutting down its socket when the task is deleted; this should
            # prevent lingering sockets
            with self.task_mgmt_lock:
                # NOTE: the task may have been cancelled during the negotation
                # protocol and a different task for that IP address may have
                # been registered
                if self.tasks.get(ipaddr) != task_id:
                    log.warning("Task #%s for IP %s was cancelled during "
                                "negotiation", task_id, ipaddr)
                    return
                s = self.handlers.setdefault(task_id, set())
                s.add(ctx)

            try:
                with protocol:
                    protocol.handle()
            except CuckooOperationalError as e:
                log.error(e)
            finally:
                with self.task_mgmt_lock:
                    s.discard(ctx)
                ctx.cancel()
                if ctx.buf:
                    # This is usually not a good sign
                    log.warning("Task #%s with protocol %s has unprocessed "
                                "data before getting disconnected",
                                task_id, protocol)

        finally:
            task_log_stop(task_id)

    def negotiate_protocol(self, task_id, ctx):
        header = ctx.read_newline()
        if " " in header:
            command, version = header.split()
            version = int(version)
        else:
            command, version = header, None
        klass = self.commands.get(command)
        if not klass:
            log.warning("Task #%s: unknown netlog protocol requested (%r), "
                        "terminating connection.", task_id, command)
            return
        ctx.command = command
        return klass(task_id, ctx, version)

class ResultServer(object):
    """Manager for the ResultServer worker and task state."""
    __metaclass__ = Singleton

    def __init__(self):
        ip = config("cuckoo:resultserver:ip")
        port = config("cuckoo:resultserver:port")
        pool_size = config('cuckoo:resultserver:pool_size')

        sock = gevent.socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            sock.bind((ip, port))
        except (OSError, socket.error) as e:
            if e.errno == errno.EADDRINUSE:
                raise CuckooCriticalError(
                    "Cannot bind ResultServer on port %d "
                    "because it was in use, bailing." % port
                )
            elif e.errno == errno.EADDRNOTAVAIL:
                raise CuckooCriticalError(
                    "Unable to bind ResultServer on %s:%s %s. This "
                    "usually happens when you start Cuckoo without "
                    "bringing up the virtual interface associated with "
                    "the ResultServer IP address. Please refer to "
                    "https://cuckoo.sh/docs/faq/#troubles-problem "
                    "for more information." % (ip, port, e)
                )
            else:
                raise CuckooCriticalError(
                    "Unable to bind ResultServer on %s:%s: %s" %
                    (ip, port, e)
                )

        # We allow user to specify port 0 to get a random port, report it back
        # here
        _, self.port = sock.getsockname()
        sock.listen(128)

        self.thread = threading.Thread(target=self.create_server,
                                       args=(sock, pool_size))
        self.thread.daemon = True
        self.thread.start()

    def add_task(self, task, machine):
        """Register a task/machine with the ResultServer."""
        self.instance.add_task(task.id, machine.ip)

    def del_task(self, task, machine):
        """Delete running task and cancel existing handlers."""
        self.instance.del_task(task.id, machine.ip)

    def create_server(self, sock, pool_size):
        if pool_size:
            pool = gevent.pool.Pool(pool_size)
        else:
            pool = 'default'
        self.instance = GeventResultServerWorker(sock, spawn=pool)
        self.instance.do_run()

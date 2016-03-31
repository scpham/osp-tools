#!/usr/bin/env python

"""

Ported from Kerry Miles (kemiles@cisco.com) divvy_cp.sh


"""

__author__ = 'Scott Pham (scpham@cisco.com)'
__date__ = '3/11/16'
__version__ = '0.1'
# Export Methods
__all__ = []

import Queue
import argparse
import getpass
import os
import sys
import threading
import time
from subprocess import Popen, PIPE

try:
    import click

    skip_progress_bar = 0
except ImportError:
    skip_progress_bar = 1
import paramiko
import logging


class CopyFu(object):
    def __init__(self, streams=10, **kwargs):
        """Object Init"""

        self.progress_queue = Queue.Queue()
        self.filename = kwargs.get('filename')
        self.streams = streams
        self.username = kwargs.get('username')
        self.hostname = kwargs.get('hostname')
        self.dest_file = kwargs.get('destination_file')
        self.ssh_key = kwargs.get('ssh_key')
        self.dev_null = open(os.devnull, 'w')
        log_format = '%(filename)s: %(levelname)s: %(funcName)s(): %(lineno)d:\t %(message)s'
        logging.basicConfig(format=log_format)
        self.logger = logging.getLogger('CopyFu')
        self.logger.setLevel(logging.INFO)

        self.start_time = time.time()
        self.nogzip = kwargs.get('nogzip')
        self.ssh_compression = kwargs.get('ssh_compression')

        self.debug = kwargs.get('debug')
        if self.debug:
            self.logger.setLevel(logging.DEBUG)

        self.ssh_args = dict(
            hostname=self.hostname,
            username=self.username,
            allow_agent=True,
            look_for_keys=True,
            compress=False
        )

        if self.ssh_key:
            self.ssh_args['key_filename'] = self.ssh_key

        if self.ssh_compression:
            self.logger.debug("Enabling SSH Compression")
            self.ssh_args['compress'] = True

        if kwargs.get('get_password'):
            self.password = getpass.getpass()
            self.ssh_args['password'] = self.password
            self.ssh_args['allow_agent'] = False
            self.ssh_args['look_for_keys'] = False
        else:
            self.password = None
            # self.stoprequest = threading.Event()

    def _generate_queue_items(self):
        """ Generates List of Offsets """

        self.file_size = os.path.getsize(self.filename)
        self.logger.debug("File Size: %s" % self.file_size)
        self.total_blocks = self.file_size / 4096
        self.logger.debug("Total Blocks: %s" % self.total_blocks)

        self.blocks_per_stream = self.total_blocks / self.streams
        self.logger.debug("Streams: %s" % self.streams)
        self.blocks_remainder = self.total_blocks % self.streams
        self.logger.debug("Left Over Blocks: %s" % self.blocks_remainder)

        offset = 0
        self.queue = []
        while offset < self.total_blocks:
            self.queue.append(offset)
            offset += self.blocks_per_stream

    def start_threads(self):
        """ Create and Start Threads for Copying """

        # Generate Queue Items
        self._generate_queue_items()

        self.logger.debug(
            "Copying File: %s With File Size: %s to Destination File: %s With %s Streams: %s Blocks Per Stream with Total Blocks: %s" % (
                self.filename, self.file_size, self.dest_file, self.streams, self.blocks_per_stream, self.total_blocks))

        pool = []
        last_item = self.queue[-1]
        for item in self.queue:
            if last_item == item:
                pool.append(threading.Thread(target=self.copy, args=(item,)))
            else:
                pool.append(threading.Thread(target=self.copy, args=(item, self.blocks_per_stream)))

        # TODO: Need to make sure the print statement isn't done until the thread is completed.
        # TODO: Move the while for bar.next to be more generic
        if self.debug or skip_progress_bar:
            for thread in pool:
                thread.start()
                # Need to throttle the ssh connections
                time.sleep(1)
        else:
            with click.progressbar(length=len(self.queue * 2), label="%s" % self.dest_file) as bar:

                for thread in pool:
                    thread.start()
                    # Need to throttle the ssh connections
                    time.sleep(1)
                    bar.next()

                max_items = len(self.queue)
                while True:
                    try:
                        if max_items == 0:
                            break
                        self.progress_queue.get(True, 0.05)
                        bar.next()
                        max_items -= 1
                    except Queue.Empty:
                        continue

        self.end_time = time.time()
        temp = self.end_time - self.start_time

        hours = temp // 3600
        temp = temp - 3600 * hours
        minutes = temp // 60
        seconds = temp - 60 * minutes
        print "Total Number Of Seconds: %s" % temp
        print('Elapsed Time: %02d:%02d:%02d' % (hours, minutes, seconds))

    def copy(self, offset, block_count=-1):
        """ Perform Copy Operation Based on Offset and Block Count"""
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh_client.connect(**self.ssh_args)
        self.ssh_transport = ssh_client.get_transport()
        ssh_channel = self.ssh_transport.open_session()

        thread_name = threading.currentThread().getName()
        self.logger.debug("Copying Offset: %s Block Count %s on Thread %s" % (offset, block_count, thread_name))

        # Read DD Process PIPED to gzip Process
        read_dd_cmd = ['dd', "if=%s" % self.filename, 'bs=4096', "skip=%s" % offset, ]
        if block_count != -1:
            read_dd_cmd.append("count=%s" % block_count)

        read_dd_process = Popen(read_dd_cmd, stdout=PIPE, stderr=self.dev_null)
        write_dd_cmd = "dd conv=notrunc of=%s bs=4096 seek=%s" % (self.dest_file, offset)

        if self.nogzip:
            self.logger.debug("Disabling gzip option")
            stream_stdout, stream_stdin = read_dd_process.communicate()
        else:
            self.logger.debug("gzip option will be used")
            gzip_process = Popen(['gzip', '-c'], stdin=read_dd_process.stdout, stdout=PIPE, stderr=self.dev_null)
            # Close this in case gzip fails and it won't leave this process hanging around
            read_dd_process.stdout.close()
            stream_stdout, stream_stdin = gzip_process.communicate()
            write_dd_cmd = "%s %s" % ('gzip -dc |', write_dd_cmd)

        ssh_channel.setblocking(0)
        ssh_channel.exec_command(write_dd_cmd)
        self.logger.debug("Sending Thread %s %s bytes" % (thread_name, sys.getsizeof(stream_stdout)))

        ssh_channel.sendall("%s" % stream_stdout)
        # Need to call shutdown(2) and recv_exit_status for this to flush all data sent
        ssh_channel.shutdown(2)
        self.logger.debug("Thread %s Exit Status %s" % (thread_name, ssh_channel.recv_exit_status()))

        ssh_client.close()

        self.progress_queue.put(block_count)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-H', '--hostname', dest='hostname', type=str, required=True, help="Hostname to copy file to")
    parser.add_argument('-d', '--dest', dest='destination_file', required=True, help="Destination File")
    parser.add_argument('-f', '--filename', dest='filename', type=str, required=True, help="Filename")
    parser.add_argument('-p', '--password', dest='get_password', default=False, action='store_true',
                        help="Supply Password")
    parser.add_argument('-k', '--key', dest='ssh_key', type=str, help="Supply SSH Key")
    parser.add_argument('-u', '--username', dest='username', type=str, required=True, help="Provide User name")
    parser.add_argument('-s', '--streams', dest='streams', type=int, help="How Many SSH Copies jobs to start")
    parser.add_argument('-c', '--ssh_compression', default=False, dest='ssh_compression', action='store_true',
                        help='Enable SSH Compression Flag')
    parser.add_argument('-z', '--nogzip', dest='nogzip', default=False, action='store_true',
                        help='Disable gzip compression')
    parser.add_argument('--debug', dest='debug', action='store_true', help="Show Debug")

    args = parser.parse_args()

    copyfu_args = {}
    for arg in vars(args):
        value = getattr(args, arg)
        if value is not None:
            copyfu_args[arg] = value

    copyfu = CopyFu(**copyfu_args)
    copyfu.start_threads()

#!/usr/bin/python

# A simple example of how to use pcapy. This needs to be run as root.

import datetime
import gflags
import pcapy
import sys

FLAGS = gflags.FLAGS
gflags.DEFINE_string('i', 'eth0', 'The name of the interface to monitor')


def main(argv):
  # Parse flags
  try:
    argv = FLAGS(argv)
  except gflags.FlagsError, e:
    print FLAGS

  print 'Opening %s' % FLAGS.i

  # Arguments here are:
  #   device
  #   snaplen (maximum number of bytes to capture _per_packet_)
  #   promiscious mode (1 for true)
  #   timeout (in milliseconds)
  cap = pcapy.open_live(FLAGS.i, 100, 1, 0)

  # Read packets -- header contains information about the data from pcap,
  # payload is the actual packet as a string
  (header, payload) = cap.next()
  while header:
    print ('%s: captured %d bytes, truncated to %d bytes'
           %(datetime.datetime.now(), header.getlen(), header.getcaplen()))

    (header, payload) = cap.next()


if __name__ == "__main__":
  main(sys.argv)

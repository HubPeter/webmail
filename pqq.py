#!/usr/bin/python

# A simple example of how to use pcapy. This needs to be run as root.

import datetime
import gflags
import pcapy
import sys
import string
from impacket.ImpactDecoder import *

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
  cap = pcapy.open_live(FLAGS.i, 2048, 1, 0)
  #host tcp 
  cap.setfilter('tcp port 80')

  # Read packets -- header contains information about the data from pcap,
  # payload is the actual packet as a string
  (header, payload) = cap.next()
  # Now you have a packet and his data
  #p = re.compile('^(palm).*')
  filename='data'
  FILE = open(filename,'w')
  while header:
    #print ('%s: captured %d bytes, truncated to %d bytes'%(datetime.datetime.now(), header.getlen(), header.getcaplen()))
    #get source address
    index = payload.find('sendmailname=')
    i_end = payload.find('&', index, index+37)
    if index != -1 :
	print payload
	print 'A qq mail captured:'
	print '  From:  '+payload[index+13:i_end]
    #get destination address
    index = payload.find('%22<')
    i_end = payload.find('>', index, index+30)
    if index != -1:
	print '  To:  '+payload[index+4:i_end]
    #Send time
    index = payload.find('cgitm=')
    i_end = payload.find('&', index, index+23)
    if index != -1:
	send_time = payload[index+6:i_end]
	date_time = datetime.datetime.fromtimestamp(long(send_time)/1000)	
	print '  Sendtime:  ',
	print date_time
    index = payload.find('subject=')#get subject start position
    i_end = payload.find('&', index, index+20)#get subject end position
    if index != -1:
	print '  subject:  '+payload[index+8:i_end]
    index = payload.find('<div>')
    i_end = payload.find('</div>')
    if index != -1:
    	print '  content:  '+payload[index+5:i_end]+'\n'
    #print TCPDecoder().decode(payload)

    (header, payload) = cap.next()

  FILE.close()
if __name__ == "__main__":
  main(sys.argv)

#/env/python

import os,sys,json,socket,struct
import bisect

def ip2n(s):
  """
  >>> ip2n('0.0.0.0')
  0
  >>> ip2n('0.0.0.1')
  1
  >>> ip2n('0.0.1.1')
  257
  >>> ip2n('1.0.0.1')
  16777217
  >>> ip2n('192.0.2.1')
  3221225985
  """
  x = socket.inet_aton(s)
  return ord(x[0]) << 24 | ord(x[1]) << 16 | ord(x[2]) << 8 | ord(x[3])

def n2ip(n):
  """
  >>> n2ip(0)
  '0.0.0.0'
  >>> n2ip(1)
  '0.0.0.1'
  >>> n2ip(257)
  '0.0.1.1'
  >>> n2ip(3221225985)
  '192.0.2.1'
  """
  packed_value = struct.pack('!I', n)
  return socket.inet_ntoa(packed_value)
  #return ord(x[0]) << 24 | ord(x[1]) << 16 | ord(x[2]) << 8 | ord(x[3])

def mid(t, a, b):
    """
    >>> mid('abc', 'a', 'b')
    ''
    >>> mid('abcde', 'b', 'd')
    'c'
    >>> mid('abcde', 'a', 'd')
    'bc'
    >>> mid('abc', 'a', 'c')
    'b'
    >>> mid('ab', 'a', 'b')
    ''
    >>> mid('ab', 'a', 'd')
    >>> mid('ab', 'c', 'd')
    """
    ia = t.find(a)
    if -1 != ia:
        ia += len(a)
        ib = t.find(b, ia)
        if -1 != ib:
            return t[ia : ib]
    return None



class Item:
  def __init__(self, start=0, end=0, name=None, desc=None):
    self.start = start
    self.end = end
    self.name = name
    self.desc = desc

  def key(self):
    return self.start

  def __cmp__(self, other):
    return cmp(self.start, other.start)

  def __hash__(self):
    return self.start

  def __repr__(self):
    return "%s(%s - %s %s)" % (self.__class__, n2ip(self.start), n2ip(self.end), self.name)


class AddressLib():
  def find(self, ip):
    if isinstance(ip, str):
      ip = ip2n(ip)

    i = bisect.bisect_left(self.seq, Item(ip,ip))
    assert i, ip
    return self.seq[i - 1]

  def __init__(self, a):
    assert(isinstance(a, list))
    self.seq = a

  @staticmethod
  def parse_whois(c):
    # inetnum:        27.16.0.0 - 27.31.255.255
    s = mid(c, "inetnum:", '\n').strip()
    start,end = s.split('-')
    start = ip2n(start.strip())
    end = ip2n(end.strip())
    # netname:        CHINANET-HB
    name = mid(c, 'netname:', '\n').strip()
    return start, end, name

  @staticmethod
  def create_from_whois_files(pat):
    import glob
    col = set()

    for f in glob.glob(pat):
      c = open(f, 'r').read()
      try:
        start, end, name = AddressLib.parse_whois(c)
      except:
        print 'file %s parse failed\n' % f
        continue
      item = Item(start, end, name)
      col.add(item)

    return AddressLib(sorted([i for i in col]))

  def __repr__(self):
    return "%s(%r)" % (self.__class__, self.__dict__)

if __name__ == '__main__':
  lib = AddressLib.create_from_whois_files('whois/*')
  for i in ['1.204.0.1', '1.10.0.1']:
    print i, lib.find(i)

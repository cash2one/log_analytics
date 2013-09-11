#/env/python

import os,sys,json,socket,struct
import bisect

import time

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
    return "%s(%s - %s %s in %s)" % (self.__class__, n2ip(self.start), n2ip(self.end), self.name, self.desc)

def find_province(c):
  """
  >>> find_province("address:        Shang Di East ROAD,Hai Dian District Beijing,P.R.China")
  'beijing'
  TODO: use descr section (not address)
  """
  name_set = ('tianjin',
    'hebei',
    'shanxi',
    'liaoning',
    'neimenggu',
    'jilin',
    'heilongjiang',
    'shanghai',
    'jiangsu',
    'zhejiang',
    'anhui',
    'fujian',
    'jiangxi',
    'shandong',
    'henan',
    'hubei',
    'hunan',
    'guangdong',
    'guangxi',
    'hainan',
    'chongqing',
    'sichuan',
    'guizhou',
    'yunnan',
    'tibet',
    'shaanxi',
    'gansu',
    'qinghai',
    'ningxia',
    'xinjiang',
    'hongkong',
    'beijing',
    'macau',
    'telecom',
    'jingrong street',
    'unicom',
    'university',
    'taiwan')
  lc = c.lower()
  lines = lc.split('\n')
  for line in lines:
    if line.find('descr:') == 0: 
      for i in name_set:
        if i in line:
          return i
  for line in lines:
    if line.find('addr:') == 0: 
      for i in name_set:
        if i in line:
          return i + '_'
  
  return 'none'

def parse_whois(c):
  """
  >>> c = open("whois/58.83.0.0", 'rb').read()
  >>> parse_whois(c)
  (978518016, 978583551, 'CenturyNetwork', 'beijing')
  >>> c = open("whois/59.44.0.0", 'rb').read()
  >>> parse_whois(c)
  (978518016, 978583551, 'CenturyNetwork', 'beijing')
  """
  s = mid(c, "inetnum:", '\n').strip()
  start,end = s.split('-')
  start = ip2n(start.strip())
  end = ip2n(end.strip())
  # netname:        CHINANET-HB
  name = mid(c, 'netname:', '\n').strip()
  province = find_province(c)
  return start, end, name, province

class AddressLib():
  def find(self, ip):
    if isinstance(ip, str):
      ip = ip2n(ip)

    i = bisect.bisect_left(self.seq, Item(ip,ip))
    # assert i, ip
    # print 'find:', i, n2ip(ip), self.seq[i-1], self.seq[i], self.seq[i+1]
    a = self.seq[i]
    if ip >= a.start:
      return self.seq[i]
    else:
      return self.seq[i-1]

  def __init__(self, a):
    assert(isinstance(a, list))
    self.seq = a

  @staticmethod
  def create_from_whois_files(pat):
    import glob
    col = set()

    file_count = 0

    for f in glob.glob(pat):
      #file_count += 1
      #if file_count > 100:
      #  break
      c = open(f, 'r').read()
      try:
        start, end, name, province = parse_whois(c)
      except:
        print 'file %s parse failed\n' % f
        continue
      item = Item(start, end, name, province)
      col.add(item)

    return AddressLib(sorted([i for i in col]))

  @staticmethod
  def create_from_iplib(fn = None):
    if fn is None:
      fn = "iplib.txt"

    col = set()
    for line in open(fn, 'rb'):
      line = line.strip('\n\r')
      start, end, district = line.split(',')

      item = Item(ip2n(start), ip2n(end), district, district)
      col.add(item)
    return AddressLib(sorted(col))


  def __repr__(self):
    return "%s(%r)" % (self.__class__, self.__dict__)

if __name__ == '__main__':
  if False:
    lib = AddressLib.create_from_whois_files('whois/*')
  else:
    lib = AddressLib.create_from_iplib('iplib.txt')

  start = time.time()
  for i in ['222.240.144.143', '222.240.144.144', '1.204.0.1', '1.10.0.1']:
    print '[%.4f]' % (time.time() - start), i, lib.find(i),
    print 





#!/usr/bin/env python
# -*- coding: utf8 -*-

import sys,re
import heapq
#import apachelog
import addresslib

class Stat():
  """
  >>> s = Stat()
  >>> s.add(1)
  >>> s.average
  1.0
  >>> s.add(2)
  >>> s.samples
  [1, 2]
  >>> s.average
  1.5
  >>> for x in range(3,10): s.add(x)
  >>> s.pecent_90_average
  4.5
  """
  def __init__(self, key = None):
    self.samples = []
    self.key = key

  def __repr__(self):
    return "%s(%r)" % (self.__class__, self.__dict__)

  def add(self, t):
    self.samples.append(t)

  @property
  def average(self):
    return float(sum(self.samples)) / len(self.samples)

  @property
  def count(self):
    return len(self.samples)

  @property
  def pecent_90_average(self):
    n = int(0.9 * len(self.samples))
    if n < 1:
      return self.average
    heapq.heapify(self.samples)
    x = heapq.nsmallest(n, self.samples)
    return float(sum(x)) / len(x)

def parse_cc_log(line):
  """
  >>> parse_cc_log('1370016000.000      1 58.253.216.21 TCP_HIT/200 61499 GET http://img.spriteapp.cn/ws/img/icon.jpg  - NONE/- image/jpeg "http://www.budejie.com/" "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.1 (KHTML, like Gecko) Maxthon/3.0 Chrome/22.0.1229.79 Safari/537.1" -')
  ('58.253.216.21', 61499, 1)
  """
  arr = [x for x in line.split(' ') if x]
  t, ip = arr[1],arr[2]
  if not t.isdigit():
    return

  content_length = int(arr[4])
  return ip, content_length, int(t)

parts = [
    r'(?P<host>\S+)',                   # host %h
    r'(?P<ip>\S+)',                     # 
    r'\S+',                             # indent %l (unused)
    r'\S+',                             # indent %l (unused)
    r'\[(?P<time>.+)\]',                # time %t
    r'"(?P<request>.+)"',               # request "%r"
    r'(?P<status>[0-9]+)',              # status %>s
    r'(?P<size>\S+)',                   # size %b (careful, can be '-')
    r'"(?P<referer>[^ ]*)"',            # referer "%{Referer}i"
    r'"(?P<agent>[^\"]*)"',             # user agent "%{User-agent}i"
    r'"([^\"]*)"',                  # referer "%{Referer}i"
    r'([0-9]+)',                        # status %>s
    r'(?P<request_time>\S+)',           # size %b (careful, can be '-')
  ]

pattern = re.compile(r'\s+'.join(parts)+r'\s.*\Z')

def parse_self_log(line):
  """
  >>> parse_self_log('api.budejie.com 183.42.210.157 - - [04/Jun/2013:09:56:02 +0800] "GET /api/api_open.php?c=data&a=amount&maxid=2456307&type=10&tag&version=41&from=android&market=anzhi HTTP/1.1" 200 15 "-" "Apache-HttpClient/UNAVAILABLE (java 1.4)" "-"  200 0.002 192.168.133.100:8000 0.002')
  ('183.42.210.157', 15, 2)
  >>> parse_self_log('api.budejie.com 75.149.2.165 - - [30/May/2013:10:30:46 +0800] "GET /ad/api_open.php?c=ad&a=get&app=54&pos=13&os=1&client=iPhone&market=&appID=485531486&appName=baisibudejie&version=1.9.1&device=iPhone%204S&userID=&userSex=&jailbroken=0&openUDID=59179e056ac71bcd1afbee64016483bc1597e541&mac=9C:20:7B:02:38:E6&udid=&dataType=app111 HTTP/1.0" 200 2468 "-" "MyWeiboJingXuan/1.9.1 CFNetwork/609.1.4 Darwin/13.0.0" "192.168.1.58, 192.168.1.58, 127.0.0.1"  200 0.003 192.168.133.101:8000 0.304')
  ('75.149.2.165', 2468, 3)
  """
  global pattern
  m = pattern.match(line)
  if not m:
    return
  d = m.groupdict()
  return d['ip'], int(d['size']), int(float(d['request_time']) * 1000)


def process(f):
  al = addresslib.AddressLib.create_from_whois_files('whois/*')

  #format = r'%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"'
  #p = apachelog.parser(format)

  # < 50k
  # 50-100k
  # > 100k

  r0 = {}
  r1 = {}
  r2 = {}
  c = 0
  
  for line in f:
    if line.startswith('#'):
      continue
    line = line.strip('\n')
    
    try:
      ip = None
      ip, content_length, request_time = parse_cc_log(line)
      seg = al.find(ip)
    except Exception,e:
      print >> sys.stderr, ip, line
      continue

    #print ip, seg

    if content_length < 50*1024:
      r = r0
    elif content_length < 100*1024 and content_length > 50 * 1024:
      r = r1
    else:
      r = r2
    s = r.setdefault(seg, Stat(seg))
    s.add(request_time)

    c = c + 1
    if c > 10000000:
      break
  return r0,r1,r2

def output(r, f):
  sr = sorted(r, key = lambda x: x.count, reverse=True)
  for i in sr:
    print >> f, "%s(%s) %d %d %d" % (i.key.name, addresslib.n2ip(i.key.start), i.count, i.average, i.pecent_90_average)

if __name__ == '__main__':
  ra = process(open(sys.argv[1], 'r'))

  try:
    os.mkdir(sys.argv[2])
  except:
    pass
  
  f = open('%s/less_than_50k.txt' % sys.argv[2], 'w')
  print >> f, '网段 访问次数 平均 最快90%平均'
  output(ra[0].values(), f)

  f = open('%s/less_than_100k.txt' % sys.argv[2], 'w')
  print >> f, '网段 访问次数 平均 最快90%平均'
  output(ra[1].values(), f)

  f = open('%s/big_than_100k.txt' % sys.argv[2], 'w')
  print >> f, '网段 访问次数 平均 最快90%平均'
  output(ra[2].values(), f)



#!/usr/bin/env python

import re, sys

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
    r'"(?P<_>[^ ]*)"',                  # referer "%{Referer}i"
    r'([0-9]+)',                        # status %>s
    r'(?P<request_time>\S+)',           # size %b (careful, can be '-')
  ]

pattern = re.compile(r'\s+'.join(parts)+r'\s.*\Z')

# api.budejie.com 220.178.5.114 - - [04/Jun/2013:09:56:02 +0800] "GET /ad/udid HTTP/1.1" 200 943 "-" 
# "%E4%B8%8D%E5%BE%97%E5%A7%90%E7%9A%84%E7%A7%98%E5%AF%86/1.4 CFNetwork/609.1.4 Darwin/13.0.0" 
# "-"  200 0.002 192.168.133.101:8000 0.002

#m = pattern.match(s)
#print m, m.groupdict()

for line in sys.stdin:
  m = pattern.match(line.strip('\n'))
  if not m:
    print line
    continue

  res = m.groupdict()
  #print res
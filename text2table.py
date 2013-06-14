#!/usr/bin/env python
# -*- coding: utf8 -*-


import sys

CSS = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<style type="text/css">
table.gridtable {
  font-family: verdana,arial,sans-serif;
  font-size:12px;
  color:#333333;
  border-width: 1px;
  border-color: #666666;
  border-collapse: collapse;
}
table.gridtable th {
  border-width: 1px;
  padding: 2px;
  border-style: solid;
  border-color: #666666;
  background-color: #dedede;
}
table.gridtable td {
  border-width: 1px;
  padding: 2px;
  border-style: solid;
  border-color: #666666;
  background-color: #ffffff;
}
</style>
</head>
<body>
<table class="gridtable">"""

ID = "gridtable"

print CSS

header = True

for line in sys.stdin:
  line = line.strip('\n\r')
  cells = line.split(' ')

  cells[0] = cells[0].replace(' 00:00:00', '')

  if header:
    header = False
    a = ['<tr>',
      '\n '.join(['<th>%s</th>' % cell for cell in cells]),
      '</tr>'
    ]
    print ''.join(a)
  else:
    a = ['<tr>',
        ''.join(['<td>%s</td>' % cell for cell in cells]),
        '</tr>'
      ]
    print ''.join(a)

print """</table></body></html>"""


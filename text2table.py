#!/usr/bin/env python
# -*- coding: utf8 -*-


import sys

def convert(text):
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
  <table class="gridtable">\n"""

  ID = "gridtable"

  ret = CSS

  header = True

  for line in text.split('\n'):
    line = line.strip('\n\r')
    cells = line.split(' ')

    cells[0] = cells[0].replace(' 00:00:00', '')

    if header:
      header = False
      a = ['<tr>',
        '\n '.join(['<th>%s</th>' % cell for cell in cells]),
        '</tr>\n'
      ]
      ret += ''.join(a)
    else:
      a = ['<tr>',
          ''.join(['<td>%s</td>' % cell for cell in cells]),
          '</tr>\n'
        ]
      ret += ''.join(a)

  ret += """</table></body></html>\n"""
  return ret

if __name__ == '__main__':
  print convert(sys.stdin)

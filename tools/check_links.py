#!/usr/bin/python

from __future__ import print_function
import os
import re
import sys

link_re = re.compile('\[' + '[^\[\]]+' + '\]' + '\(' + '([^\(\)]+)' + '\)')

if len(sys.argv) < 3:
	print('Usage: <root_dir> <doc_files>...')
	sys.exit(1)

root = sys.argv[1]
docs = sys.argv[2:]

links = []

for doc in docs:
	with open(doc) as f:
		data = f.read()
		r = link_re.findall(data)
		for link in r:
			links += [(doc, link)]

def filter_link(args):
	(doc, link) = args
	if link.startswith('http'):
		return False
	if link.startswith('#'):
		return False
	if link.startswith('mailto'):
		return False
	return True

links = list(filter(filter_link, links))

def fix_link(args):
	(doc, link) = args
	link = link.split('#')[0]
	link = link.split('?')[0]
	return (doc, link)

links = list(map(fix_link, links))

errors = []

def check_link(args):
	(doc, link) = args
	path = os.path.dirname(doc)
	full_link = None
	if link[0] == '/':
		link = link[1:]
		full_link = os.path.join(root, link)
	else:
		full_link = os.path.join(root, path, link)
	if not os.path.exists(full_link):
		return False
	return True

for link in links:
	if not check_link(link):
		errors += [link]

if len(errors) == 0:
	print('%d links checked: OK' % (len(links),))
	sys.exit(0)

for (doc, link) in errors:
	print('File %s linked from %s not found' % (link, doc))

sys.exit(2)

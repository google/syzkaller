#!/usr/bin/python

import sys

import kconfiglib

# Extract all positively mentioned configs.
def unpack_dep_expr(expr):
	r = set()
	if expr.__class__ is kconfiglib.Symbol:
		if expr.name in ['y', 'm', 'n']:
			return r
		r.add(expr)
		return r
	if expr.__class__ is kconfiglib.Choice:
		r.update(expr.syms)
		r.add(expr)
		return r
	assert expr.__class__ is tuple
	if expr[0] is kconfiglib.NOT:
		return r
	r.update(unpack_dep_expr(expr[1]))
	r.update(unpack_dep_expr(expr[2]))
	return r

# Extract dependencies recuresively.
def extract_deps(item):
	deps = set()
	handled = set()
	def extract_deps_impl(item):
		if item in handled:
			return
		handled.add(item)
		sub = unpack_dep_expr(item.direct_dep)
		deps.update(sub)
		for sub_item in sub:
			extract_deps_impl(sub_item)
	extract_deps_impl(item)
	return deps

def extract_nodes_deps(nodes):
	deps = set()
	for node in nodes:
		deps.update(extract_deps(node.item))
	return deps

if len(sys.argv) < 3:
	sys.exit('Usage: {} usb.config'.format(sys.argv[0]))

kconf = kconfiglib.Kconfig(warn=False)
kconf.load_config(sys.argv[2])

core_usb_syms_names = ['USB_SUPPORT', 'USB', 'USB_ARCH_HAS_HCD']
core_usb_syms = set()
for name in core_usb_syms_names:
	core_usb_syms.add(kconf.syms[name])

usb_nodes = set()
for node in kconf.node_iter():
	if node.item.__class__ not in [kconfiglib.Symbol, kconfiglib.Choice]:
		continue
	if len(core_usb_syms.intersection(extract_deps(node.item))) > 0:
		usb_nodes.add(node)
print('usb_nodes', len(usb_nodes))

deps = extract_nodes_deps(usb_nodes)
print('deps', len(deps))

# Only leave the last choice.
exclude = set()
for dep in deps:
	if dep.__class__ is not kconfiglib.Choice:
		continue
	for sym in dep.syms[:-1]:
		exclude.add(sym)
print('exclude', len(exclude))

kconf = kconfiglib.Kconfig(warn=False)
kconf.load_config()

for dep in deps:
	if dep.__class__ is kconfiglib.Symbol:
		if dep in exclude:
			continue
		kconf.syms[dep.name].set_value(2)

for node in list(usb_nodes):
	if node.item.__class__ is kconfiglib.Symbol:
		if node.item in exclude:
			continue
		kconf.syms[node.item.name].set_value(2)

kconf.write_config()

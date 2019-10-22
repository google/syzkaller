#!/usr/bin/python

from __future__ import print_function

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

# Extract item dependencies recursively.
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

# Extract all dependencies for a list of nodes.
def extract_nodes_deps(nodes):
	deps = set()
	for node in nodes:
		deps.update(extract_deps(node.item))
	return deps

def item_depends_on_syms(item, syms):
	return len(syms.intersection(extract_deps(item))) > 0

if len(sys.argv) < 3:
	sys.exit('Usage: {} usb.config'.format(sys.argv[0]))

# Load config given in SCRIPT_ARG.
base_kconf = kconfiglib.Kconfig(warn=False)
base_kconf.load_config(sys.argv[2])

# Make a list of some core USB symbols.
# Some USB drivers don't depend on core USB symbols, but rather depend on a
# generic symbol for some input subsystem (e.g. HID), so include those as well.
core_usb_syms_names = ['USB_SUPPORT', 'USB', 'USB_ARCH_HAS_HCD', 'HID']
core_usb_syms = set([base_kconf.syms[name] for name in core_usb_syms_names])

# Extract all enabled (as =y or =m) USB nodes. A USB node is detected as a
# node, which depends on least one USB core symbol.
usb_nodes = set()
for node in base_kconf.node_iter():
	if node.item.__class__ not in [kconfiglib.Symbol, kconfiglib.Choice]:
		continue
	if node.item.tri_value == 0:
		continue
	if item_depends_on_syms(node.item, core_usb_syms):
		usb_nodes.add(node)
print('USB nodes:', len(usb_nodes))

# Extract USB nodes dependencies.
deps = extract_nodes_deps(usb_nodes)
print('USB nodes dependencies:', len(deps))

# Extract choice options to be disabled to only leave the last option enabled
# for each choice.
exclude = set()
for dep in deps:
	if dep.__class__ is not kconfiglib.Choice:
		continue
	for sym in dep.syms[:-1]:
		exclude.add(sym)
print('Excluded choice options:', len(exclude))

# Load current .config.
new_kconf = kconfiglib.Kconfig(warn=False)
new_kconf.load_config()

# First, enable all extracted dependencies.
for dep in deps:
	if dep.__class__ is kconfiglib.Symbol:
		if dep in exclude:
			continue
		new_kconf.syms[dep.name].set_value(2)

# Then, enable extracted USB nodes as =y.
for node in list(usb_nodes):
	if node.item.__class__ is kconfiglib.Symbol:
		if node.item in exclude:
			continue
		new_kconf.syms[node.item.name].set_value(2)

# Now, disable USB symbols that are disabled in the base config, as they might
# have been enabled when some of the dependecies got enabled.
to_disable = []
core_usb_syms = set([new_kconf.syms[name] for name in core_usb_syms_names])
for node in new_kconf.node_iter():
	if node.item.__class__ is not kconfiglib.Symbol:
		continue
	if not item_depends_on_syms(node.item, core_usb_syms):
		continue
	sym = base_kconf.syms.get(node.item.name)
	if not sym:
		to_disable.append(node.item.name)
	if sym.tri_value == 0:
		to_disable.append(node.item.name)
for name in to_disable:
	new_kconf.syms[name].set_value(0)

# Remove testing related symbols.
blacklist = ['COMPILE_TEST']
for sym in blacklist:
	new_kconf.syms[sym].set_value(0)

new_kconf.write_config()

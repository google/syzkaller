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
def extract_item_deps(item):
	deps = set()
	handled = set()
	def extract_item_deps_impl(item):
		if item in handled:
			return
		handled.add(item)
		sub = unpack_dep_expr(item.direct_dep)
		deps.update(sub)
		for sub_item in sub:
			extract_item_deps_impl(sub_item)
	extract_item_deps_impl(item)
	return deps

# Extract all dependencies for a list of items.
def extract_items_deps(items):
	deps = set()
	for item in items:
		deps.update(extract_item_deps(item))
	return deps

# Returns true if an item depends on any of the given symbols.
def item_depends_on_syms(item, syms):
	return len(syms.intersection(extract_item_deps(item))) > 0

# A list of some core USB symbol names.
# Some USB drivers don't depend on any USB related symbols, but rather on a
# generic symbol for some input subsystem (e.g. HID), so include those as well.
core_usb_syms_names = ['USB_SUPPORT', 'USB', 'USB_ARCH_HAS_HCD', 'HID']

def extract_usb_items_and_deps(kconf):
	core_usb_syms = set([kconf.syms[name] for name in core_usb_syms_names])

	# Extract all enabled (as =y or =m) USB items.
	# A USB item is an item that depends on least one core USB symbol.
	usb_items = set()
	for node in kconf.node_iter():
		if node.item.__class__ not in [kconfiglib.Symbol, kconfiglib.Choice]:
			continue
		if node.item.__class__ is kconfiglib.Symbol and node.item.str_value == "n":
			continue
		if node.item.__class__ is kconfiglib.Choice and node.item.str_value == 0:
			continue
		if item_depends_on_syms(node.item, core_usb_syms):
			usb_items.add(node.item)

	# Extract USB items dependencies.
	dep_items = extract_items_deps(usb_items)

	# For consistency leave only the last option enabled for each choice.
	exclude = set()
	for item in dep_items:
		if item.__class__ is not kconfiglib.Choice:
			continue
		for sym in item.syms[:-1]:
			exclude.add(sym)
	dep_items = filter(lambda item: item not in exclude, dep_items)
	usb_items = filter(lambda item: item not in exclude, usb_items)

	print('USB items:', len(usb_items))
	print('USB dependencies:', len(dep_items))

	return (usb_items, dep_items)

if len(sys.argv) < 3:
	sys.exit('Usage: {} <usb1.config>,<usb2.config>,...'.format(sys.argv[0]))

# Load configs given in SCRIPT_ARG.
base_kconfs = []
for config in sys.argv[2].split(','):
	if len(config) == 0:
		continue
	kconf = kconfiglib.Kconfig(warn=False)
	kconf.load_config(config)
	base_kconfs.append(kconf)

base_items = []
for kconf in base_kconfs:
	base_items.append(extract_usb_items_and_deps(kconf))

# Load current .config.
new_kconf = kconfiglib.Kconfig(warn=False)
new_kconf.load_config()

for (usb_items, dep_items) in base_items:
	# First, enable all extracted dependencies turning =m into =y.
	for item in dep_items:
		if item.__class__ is kconfiglib.Symbol:
			value = item.str_value
			if value == "m":
				value = "y"
			new_kconf.syms[item.name].set_value(value)

	# Then, enable extracted USB items turning =m into =y.
	for item in usb_items:
		if item.__class__ is kconfiglib.Symbol:
			value = item.str_value
			if value == "m":
				value = "y"
			new_kconf.syms[item.name].set_value(value)

# Now, disable USB symbols that are disabled in all of the base configs,
# as they might have been enabled when some of the dependecies got enabled.
to_disable = []
core_usb_syms = set([new_kconf.syms[name] for name in core_usb_syms_names])
for node in new_kconf.node_iter():
	if node.item.__class__ is not kconfiglib.Symbol:
		continue
	if not item_depends_on_syms(node.item, core_usb_syms):
		continue
	disable = True
	for kconf in base_kconfs:
		sym = kconf.syms.get(node.item.name)
		if not sym:
			continue
		if sym.tri_value == 0:
			continue
		disable = False
		break
	if disable:
		to_disable.append(node.item.name)
for name in to_disable:
	new_kconf.syms[name].set_value(0)

# Remove testing related symbols.
blacklist = ['COMPILE_TEST']
for sym in blacklist:
	new_kconf.syms[sym].set_value(0)

new_kconf.write_config()

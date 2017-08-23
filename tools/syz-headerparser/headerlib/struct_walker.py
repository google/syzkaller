# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

'''
This module provides classes which implement AST traversal in order to extract
items belonging to a struct.
'''

import collections
import logging

from pycparser import c_ast
from header_preprocessor import HeaderFilePreprocessor


class StructWalkerException(Exception):
    pass


class StructWalker(c_ast.NodeVisitor):
    '''
    Given an ast obtained by parsing a header file, return a hierarchy
    dictionary. The ast is expected to be of type pycparser.c_ast.FileAST.

    Usage :

    >>> import tempfile
    >>> t = tempfile.NamedTemporaryFile()
    >>> contents = """
    ... #define STRUCT_SIZE 1337
    ... struct ARRAY_OF_POINTERS_CONTAINER {
    ... 	unsigned int *ptr[10];
    ... 	int **n;
    ... };
    ... struct ARRAY_CONTAINER {
    ... 	  int g[10];
    ... 		  int h[20][30];
    ... };
    ... struct REGULAR_STRUCT {
    ... 	int x;
    ... 	char *y;
    ... 	void *ptr;
    ... };
    ... struct STRUCT_WITH_STRUCT_PTR {
    ... 	struct REGULAR_STRUCT *struct_ptr;
    ... 	int z;
    ... };
    ... struct STRUCT_WITH_STRUCT_INST {
    ... 	struct REGULAR_STRUCT regular_struct_inst;
    ... 	int a;
    ... };
    ... struct STRUCT_WITH_STRUCT_ARRAY {
    ... 	struct REGULAR_STRUCT regular_struct_array[100];
    ... 	int b;
    ... };
    ... struct STRUCT_WITH_ANONYMOUS_STRUCT {
    ... 	struct {
    ... 		int g;
    ... 		int h;
    ... 		int i;
    ... 	} anonymous_struct;
    ... };
    ... struct STRUCT_WITH_ANONYMOUS_UNION {
    ... 	union {
    ... 		int t;
    ... 		char r[100];
    ... 	} anonymous_union;
    ... };
    ... struct STRUCT_WITH_STRUCT_ARRAY_SIZE_MACRO {
    ... 	struct REGULAR_STRUCT regular_struct_array[STRUCT_SIZE];
    ... };
    ... struct STRUCT_WITH_2D_ARRAY_INST {
    ... 	struct REGULAR_STRUCT regular_struct_array_2D[10][10];
    ... };
    ... struct NESTED_ANONYMOUS_STRUCT {
    ... 	struct {
    ... 		int x;
    ... 		struct {
    ... 			int y;
    ... 			int z;
    ... 		} level_2;
    ... 	} level_1;
    ... };
    ... """
	>>> t.write(contents) ; t.flush()
    >>> struct_walker = StructWalker(filenames=[t.name])
    >>> local_hierarchy = struct_walker.generate_local_hierarchy()
    >>> for k in local_hierarchy:
    ...     print k
    ...     print local_hierarchy[k]
    ARRAY_OF_POINTERS_CONTAINER
    [('unsigned int*[10]', 'ptr'), ('int**', 'n')]
    STRUCT_WITH_STRUCT_ARRAY_SIZE_MACRO
    [('struct REGULAR_STRUCT[1337]', 'regular_struct_array')]
    STRUCT_WITH_2D_ARRAY_INST
    [('struct REGULAR_STRUCT[10][10]', 'regular_struct_array_2D')]
    STRUCT_WITH_STRUCT_ARRAY
    [('struct REGULAR_STRUCT[100]', 'regular_struct_array'), ('int', 'b')]
    NESTED_ANONYMOUS_STRUCT
    [('int', 'level_1.x'), ('int', 'level_1.level_2.y'), ('int', 'level_1.level_2.z')]
    STRUCT_WITH_ANONYMOUS_STRUCT
    [('int', 'anonymous_struct.g'), ('int', 'anonymous_struct.h'), ('int', 'anonymous_struct.i')]
    STRUCT_WITH_ANONYMOUS_UNION
    [('int', 'anonymous_union.t'), ('char[100]', 'anonymous_union.r')]
    STRUCT_WITH_STRUCT_INST
    [('struct REGULAR_STRUCT', 'regular_struct_inst'), ('int', 'a')]
    ARRAY_CONTAINER
    [('int[10]', 'g'), ('int[20][30]', 'h')]
    REGULAR_STRUCT
    [('int', 'x'), ('char*', 'y'), ('void*', 'ptr')]
    STRUCT_WITH_STRUCT_PTR
    [('struct REGULAR_STRUCT*', 'struct_ptr'), ('int', 'z')]
    '''

    def __init__(self, ast=None, filenames=[], include_lines='', loglvl=logging.INFO):
        super(StructWalker, self).__init__()
        self.ast = ast
        self.filenames = filenames

        if not filenames and not ast:
            raise StructWalkerException('Specify either "filename" or "ast" to create'
                                        'StructParser object')

        if not self.ast:
            self.ast = HeaderFilePreprocessor(self.filenames, include_lines=include_lines,
                                              loglvl=loglvl).get_ast()

        self.include_lines = include_lines
        self.local_structs_hierarchy = {}
        self._setuplogging(loglvl)

    def _setuplogging(self, loglvl):
        self.logger = logging.getLogger(self.__class__.__name__)
        formatter = logging.Formatter('DEBUG:%(name)s:%(message)s')
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        sh.setLevel(loglvl)
        self.logger.addHandler(sh)
        self.logger.setLevel(loglvl)

    def _format_item(self, processed_item):
        fmt_type = processed_item['type']
        fmt_type = ' '.join(fmt_type)

        self.logger.debug('_format_item : %s', processed_item)

        if 'is_ptr' in processed_item and 'is_fnptr' not in processed_item:
            fmt_type = '%s%s' % (fmt_type, '*' * processed_item['is_ptr'])

        if 'is_array' in processed_item and 'array_size' in processed_item:
            size_str = str(processed_item['array_size']).replace(', ', '][')
            fmt_type = '%s%s' % (fmt_type, size_str)

        fmt_identifier = processed_item['identifier']

        return [(fmt_type, fmt_identifier)]

    def _recursive_process_item(self, item_ast, processed_item, parent):
        self.logger.debug('--- _recursive_process_item : %s', type(item_ast))
        if isinstance(item_ast, c_ast.Decl):
            processed_item['identifier'] = item_ast.name
            return self._recursive_process_item(item_ast.type, processed_item, item_ast)

        elif isinstance(item_ast, c_ast.TypeDecl):
            return self._recursive_process_item(item_ast.type, processed_item, item_ast)

        elif isinstance(item_ast, c_ast.IdentifierType):
            if len(item_ast.names) > 0:
                processed_item['type'] = item_ast.names
                return self._format_item(processed_item)

        elif (isinstance(item_ast, c_ast.Struct) or
              isinstance(item_ast, c_ast.Union)):
            if not item_ast.name:
                nodename, _items_list = self._traverse_ast(item_ast, toplevel=False)
                try:
                    items_list = [(i[0], '%s.%s' % (parent.declname, i[1])) for i in _items_list]
                except AttributeError as e:
                    self.logger.info('-- Encountered anonymous_struct/anonymous_union with no name')
                    raise StructWalkerException('Encountered anonymous_struct/anonymous_union with no name')

                return items_list
            else:
                processed_item['type'] = ['struct %s' % (item_ast.name)]
                return self._format_item(processed_item)

        elif isinstance(item_ast, c_ast.PtrDecl):
            if 'is_ptr' not in processed_item:
                processed_item['is_ptr'] = 0
            processed_item['is_ptr'] = processed_item['is_ptr'] + 1
            return self._recursive_process_item(item_ast.type, processed_item, item_ast)

        elif isinstance(item_ast, c_ast.ArrayDecl):
            processed_item['is_array'] = True
            if 'array_size' not in processed_item:
                processed_item['array_size'] = []
            processed_item['array_size'].append(int(item_ast.dim.value))
            return self._recursive_process_item(item_ast.type, processed_item, item_ast)

        elif isinstance(item_ast, c_ast.Enum):
            processed_item['type'] = ['enum %s' % (item_ast.name)]
            return self._format_item(processed_item)

        elif isinstance(item_ast, c_ast.FuncDecl):
            processed_item['is_fnptr'] = True
            processed_item['type'] = ['void (*)()']
            return self._format_item(processed_item)

    def _traverse_ast(self, node, toplevel=True):
        items_list = []

        # Argument structs are used as types, hence anonymous top-level
        # structs are ignored.
        if toplevel and not node.name:
            return None

        if not node.children():
            return None

        self.logger.debug('>>> Struct name = %s, coord: %s', node.name, node.coord)
        for child in node.children():
            item = self._recursive_process_item(child[1], {}, None)
            items_list.extend(item)

        self.logger.debug('_traverse_ast returns: %s', str((node.name, items_list)))
        return (node.name, items_list)

    def visit_Struct(self, node, *a):
        if node.name in self.local_structs_hierarchy:
            self.logger.info('Encountered %s again. Ignoring.', repr(node.name))
            return

        try:
            desc = self._traverse_ast(node)
        except StructWalkerException as e:
            self.logger.info('-- Exception raised by StructWalkerException in %s,'
                             'inspect manually.',
                             repr(node.name))
            self.logger.info(str(e))
            return

        if not desc:
            return

        struct_name, struct_items = desc
        self.local_structs_hierarchy[struct_name] = struct_items

    def generate_local_hierarchy(self):
        self.visit(self.ast)
        return self.local_structs_hierarchy

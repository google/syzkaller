# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

'''
This module provides classes which implement header file preprocessing.
'''

import logging
import ntpath
import os
import subprocess
import tempfile
import traceback

import pycparser

template = '''
#include <stdbool.h>
#define _GNU_SOURCE             /* See feature_test_macros(7) */

// ------ MAKE PYCPARSER HAPPY ------
#define __attribute__(...)
#define __inline inline
#define __restrict
#define __extension__
// #define __sighandler_t int
#define __user

#define __asm__(...)
#define __volatile__(...)
#define __signed__ signed
#define __int128_t unsigned long long // Hacky
#define __alignof__(...) 0

#define INIT // regex
typedef unsigned int size_t;
// ------ MAKE PYCPARSER HAPPY ------

#include <stdint.h>
%(include_lines)s
%(header_file_includes)s
'''


class HeaderFilePreprocessorException(Exception):
    '''Exceptions raised from HeaderFileParser. '''
    pass


class HeaderFilePreprocessor(object):
    '''
    Given a C header filename, perform pre-processing and return an
    ast that can be used for further processing.

    Usage :

    >>> import tempfile
    >>> t = tempfile.NamedTemporaryFile()
    >>> contents = """
    ... struct ARRAY_OF_POINTERS_CONTAINER {
    ... unsigned int *ptr[10];
    ... int **n;
    ... };
    ...
    ... struct ARRAY_CONTAINER {
    ... int g[10];
    ... int h[20][30];
    ... };
    ...
    ... struct REGULAR_STRUCT {
    ... int x;
    ... char *y;
    ... void *ptr;
    ... };
    ...
    ... struct STRUCT_WITH_STRUCT_PTR {
    ... struct REGULAR_STRUCT *struct_ptr;
    ... int z;
    ... };
    ... """
    >>> t.write(contents) ; t.flush()
    >>> h = HeaderFilePreprocessor([t.name])
    >>> ast = h.get_ast()
    >>> print type(ast)
    <class 'pycparser.c_ast.FileAST'>
    '''

    def __init__(self, filenames, include_lines='', loglvl=logging.INFO):
        self.filenames = filenames
        self.include_lines = include_lines
        self._setuplogging(loglvl)
        self._mktempfiles()
        self._copyfiles()
        self._gcc_preprocess()

    def execute(self, cmd):
        self.logger.debug('HeaderFilePreprocessor.execute: %s', cmd)
        p = subprocess.Popen(cmd, shell=True)
        try:
            os.waitpid(p.pid, 0)
        except OSError as exception:
            raise HeaderFilePreprocessorException(exception)

    def _setuplogging(self, loglvl):
        self.logger = logging.getLogger(self.__class__.__name__)
        formatter = logging.Formatter('DEBUG:%(name)s:%(message)s')
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        sh.setLevel(loglvl)
        self.logger.addHandler(sh)
        self.logger.setLevel(loglvl)

    def _copyfiles(self):
        self.execute('cp %s %s' % (' '.join(self.filenames), self.tempdir))

    def _mktempfiles(self):
        self.tempdir = tempfile.mkdtemp()
        self.temp_sourcefile = os.path.join(self.tempdir, 'source.c')
        self.temp_objectfile = os.path.join(self.tempdir, 'source.o')
        self.logger.debug(('HeaderFilePreprocessor._mktempfiles: sourcefile=%s'
                           'objectfile=%s'), self.temp_sourcefile, self.temp_objectfile)

        header_file_includes = ''
        include_lines = self.include_lines
        for name in self.filenames:
            header_file_includes = '%s#include "%s"\n' % (header_file_includes,
                                                          ntpath.basename(name))

        open(self.temp_sourcefile, 'w').write(template % (locals()))

    def _gcc_preprocess(self):
        self.execute('gcc -I. -E -P -c %s > %s'
                                        % (self.temp_sourcefile, self.temp_objectfile))

    def _get_ast(self):
        return pycparser.parse_file(self.temp_objectfile)

    def get_ast(self):
        try:
            return self._get_ast()
        except pycparser.plyparser.ParseError as e:
            raise HeaderFilePreprocessorException(e)

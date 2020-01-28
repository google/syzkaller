# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

'''
This module contains container classes for holding struct, struct fields, and a global
namespace for struct objects obtained from multiple header files.
'''

import logging

from headerlib.struct_walker import StructWalker


class StructRepr(object):
    '''
    This class is a container for a single struct type. `fr_list` is a list of all items
    inside the struct, along with type information.
    '''

    def __init__(self, struct_name, fr_list, loglvl=logging.INFO):
        self.struct_name = struct_name
        self.fr_list = fr_list
        self.global_hierarchy = {}
        self._setuplogging(loglvl)

    def __str__(self):
        return self._output_syzkaller_fmt()

    def _setuplogging(self, loglvl):
        self.logger = logging.getLogger(self.__class__.__name__)
        formatter = logging.Formatter('DEBUG:%(name)s:%(message)s')
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        sh.setLevel(loglvl)
        self.logger.addHandler(sh)
        self.logger.setLevel(loglvl)

    def _output_syzkaller_fmt(self):
        header = '%s {' % (self.struct_name)
        body = self.get_syzkaller_field_body()[:-1]
        footer = '}'
        return '\n'.join([header, body, footer])

    def get_syzkaller_field_body(self):
        '''
        Returns the metadata description for a struct field in syzkaller format.
        eg: "len    intptr".
        In cases where more than one syzkaller type maps to a native type, return
        a string with possible syzkaller types seperated by '|'.
        '''

        def _get_syzkaller_type(native_type):
            syzkaller_types = {
                'size_t'            : 'len|fileoff|intN',
                'ssize_t'           : 'len|intN',
                'unsigned int'      : 'len|fileoff|int32',
                'int'               : 'len|fileoff|flags|int32',
                'long'              : 'len|fileoff|flags|intN',
                'unsigned long'     : 'len|fileoff|flags|intN',
                'unsigned long long': 'len|fileoff|intN',
                'char*'             : 'ptr[in|out, string]|ptr[in, filename]',
                'char**'            : 'ptr[in, [ptr[in|out, string]]]',
                'void*'             : 'ptr[in|out, string]|ptr[in|out, array]',
                'void (*)()'        : 'vma',
                'uint64_t'          : 'len|int64',
                'int64_t'           : 'len|int64',
                'uint32_t'          : 'len|int32',
                'int32_t'           : 'len|int32',
                'uint16_t'          : 'len|int16',
                'int16_t'           : 'len|int16',
                'uint8_t'           : 'len|int8',
                'int8_t'            : 'len|int8',
                }
            if '[' in native_type and ']' in native_type:
                return 'array'

            # If we have a pointer to a struct object
            elif 'struct ' in native_type:
                if '*' in native_type:
                    return 'ptr|buffer|array'
                else:
                    return native_type.split(' ')[-1]

            elif 'enum ' in native_type:
                return native_type.split(' ')[-1]

            # typedef types
            return syzkaller_types.get(native_type, native_type)

        body = ''
        rows = []
        for field in self.fr_list:
            rows.append((field.field_identifier, _get_syzkaller_type(field.field_type), field.field_type))

        maxcolwidth = lambda rows, x: max([len(row[x])+5 for row in rows])
        col1_width = maxcolwidth(rows, 0)
        col2_width = maxcolwidth(rows, 1)
        for row in rows:
            body += ' '*10 + '%s%s#(%s)\n' % (row[0].ljust(col1_width), row[1].ljust(col2_width), row[2])

        return body

    def get_fields(self):
        '''
        Get a list of all fields in this struct.
        '''
        return self.fr_list

    def set_global_hierarchy(self, global_hierarchy):
        '''
        Set a reference to the global hierarchy of structs. This is useful when unrolling
        structs.
        '''
        self.global_hierarchy = global_hierarchy


class FieldRepr(object):
    '''
    This class is a container for a single item in a struct. field_type refers to the
    type of the item. field_identifier refers to the name/label of the item. field_extra
    is any item specific metadata. In cases where the field_type refers to another struct
    (whose items we are aware of), field_extra points to its StructRepr instance. This is
    used for struct unrolling in cases where an instance of "struct B" is an item inside
    "struct A".
    '''

    def __init__(self, field_type, field_identifier):
        self._field_type = field_type
        self._field_identifier = field_identifier
        self._field_extra = None

    @property
    def field_type(self):
        '''Retrieve the field type.'''
        return self._field_type
    @field_type.setter
    def field_type(self, field_type):
        self._field_type = field_type

    @property
    def field_identifier(self):
        '''Retrieve the field identifier.'''
        return self._field_identifier
    @field_identifier.setter
    def field_identifier(self, field_identifier):
        self._field_identifier = field_identifier

    @property
    def field_extra(self):
        '''Retrieve any field specific metadata object.'''
        return self._field_extra
    @field_extra.setter
    def field_extra(self, field_extra):
        self._field_extra = field_extra


class GlobalHierarchy(dict):
    '''
    This class is a global container for structs and their items across a list
    of header files. Each struct is stored key'd by the struct name, and represented
    by an instance of `StructRepr`.
    '''

    def __init__(self, filenames, loglvl=logging.INFO,
                 include_lines='', output_fmt=''):
        super(GlobalHierarchy, self).__init__()
        self.filenames = filenames
        self.include_lines = include_lines
        self.loglvl = loglvl
        self._setuplogging()
        if self.filenames:
            self.load_header_files()

    def __str__(self):
        return self._output_syzkaller_fmt()

    def _setuplogging(self):
        self.logger = logging.getLogger(self.__class__.__name__)
        formatter = logging.Formatter('DEBUG:%(name)s:%(message)s')
        sh = logging.StreamHandler()
        sh.setFormatter(formatter)
        sh.setLevel(self.loglvl)
        self.logger.addHandler(sh)
        self.logger.setLevel(self.loglvl)

    @staticmethod
    def _get_struct_name(struct_type):
        return struct_type.split()[-1]

    def _output_syzkaller_fmt(self):
        return ''

    def add_header_file(self, filename):
        '''Add a header file to the list of headers we are about to parse.'''
        self.filenames.append(filename)

    def load_header_files(self):
        '''
        Parse the list of header files and generate StructRepr instances to represent each
        struct object. Maintain a global view of all structs.
        '''
        self.logger.debug('load_header_files : %s', str(self.filenames))
        struct_walker = StructWalker(filenames=self.filenames, include_lines=self.include_lines,
                                     loglvl=self.loglvl)
        local_hierarchy = struct_walker.generate_local_hierarchy()

        for struct_name in local_hierarchy:
            fr_list = [FieldRepr(i[0], i[1]) for i in local_hierarchy[struct_name]]
            sr = StructRepr(struct_name, fr_list, loglvl=self.loglvl)
            sr.set_global_hierarchy(self)
            self["struct %s" % (struct_name)] = sr

        for struct_name in self.keys():
            sr = self[struct_name]
            for field in sr.get_fields():
                # If the item is a struct object, we link it against an
                # instance of its corresponding `sr`
                if field.field_type in self:
                    field.field_extra = self[field.field_type]

    def get_metadata_structs(self):
        '''
        Generate metadata structs for all structs that this global namespace knows about.
        '''
        metadata_structs = ""
        for struct_name in sorted(self.keys()):
            sr = self[struct_name]
            metadata_structs += str(sr) + "\n"
        return metadata_structs.strip()

# Copyright 2017 syzkaller project authors. All rights reserved.
# Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

'''
This scripts takes as input a list of header files and generates metadata
files to make syzkaller device descriptions.
'''

import argparse
import logging
import sys
import traceback

from headerlib.header_preprocessor import HeaderFilePreprocessorException
from headerlib.container import GlobalHierarchy


def main():
    """
    python parser.py --filename=A.h,B.h
    """

    parser = argparse.ArgumentParser(description='Parse header files to output fuzzer'
                                                 'struct metadata.')
    parser.add_argument('--filenames',
                        help='comma-separated header filenames',
                        dest='filenames',
                        required=True)
    parser.add_argument('--debug',
                        help='print debug-information at every level of parsing',
                        action='store_true')
    parser.add_argument('--include',
                        help='include the specified file as the first line of the processed header files',
                        required=False,
                        const='',
                        nargs='?')

    args = parser.parse_args()

    loglvl = logging.INFO

    if args.debug:
        loglvl = logging.DEBUG

    include_lines = ''
    if args.include:
        include_lines = open(args.include, 'r').read()

    try:
        gh = GlobalHierarchy(filenames=args.filenames.split(','),
                         loglvl=loglvl, include_lines=include_lines)
    except HeaderFilePreprocessorException as e:
        excdata = traceback.format_exc().splitlines()
        logging.error(excdata[-1])
        sys.exit(-1)


    print gh.get_metadata_structs()

if __name__ == '__main__':
    main()

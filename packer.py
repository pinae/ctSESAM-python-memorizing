#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Compression with DEFLATE.
"""

import zlib
import struct


class Packer(object):
    """
    You do not need to create instances of this class because compress and decompress are both static methods.
    """

    @staticmethod
    def compress(data):
        """
        Compresses the given data with the DEFLATE algorithm. The first four bytes contain the length of the
        uncompressed data.

        :param data: uncompressed data
        :type data: bytes or str
        :return: compressed data
        :rtype: bytes
        """
        compress_object = zlib.compressobj(
            zlib.Z_BEST_COMPRESSION,
            zlib.DEFLATED,
            zlib.MAX_WBITS,
            zlib.DEF_MEM_LEVEL,
            zlib.Z_DEFAULT_STRATEGY)
        if type(data) == str:
            compressed_data = compress_object.compress(data.encode('utf-8'))
            compressed_data += compress_object.flush()
            return struct.pack('!I', len(data.encode('utf-8'))) + compressed_data
        elif type(data) == bytes:
            compressed_data = compress_object.compress(data)
            compressed_data += compress_object.flush()
            return struct.pack('!I', len(data)) + compressed_data
        else:
            raise TypeError("Please pass a str or bytes to the packer.")

    @staticmethod
    def decompress(compressed_data):
        """
        Decompresses the given data. Please be aware that the first four bytes are the length of the uncompressed
        data.

        :param compressed_data: compressed data
        :type compressed_data: bytes
        :return: uncompressed data
        :rtype: bytes
        """
        if type(compressed_data) == bytes:
            try:
                return zlib.decompress(compressed_data[4:])
            except zlib.error:
                raise ValueError("The compressed data is in a wrong format.")
        else:
            raise TypeError("Please pass bytes to the packer.")

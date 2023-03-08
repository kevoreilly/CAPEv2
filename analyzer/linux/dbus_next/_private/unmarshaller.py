from ..message import Message
from .constants import HeaderField, LITTLE_ENDIAN, BIG_ENDIAN, PROTOCOL_VERSION
from ..constants import MessageType, MessageFlag
from ..signature import SignatureTree, Variant
from ..errors import InvalidMessageError

import array
import socket
from codecs import decode
from struct import unpack_from

MAX_UNIX_FDS = 16


class MarshallerStreamEndError(Exception):
    pass


class Unmarshaller:
    def __init__(self, stream, sock=None):
        self.unix_fds = []
        self.buf = bytearray()
        self.offset = 0
        self.stream = stream
        self.sock = sock
        self.endian = None
        self.message = None

        self.readers = {
            'y': self.read_byte,
            'b': self.read_boolean,
            'n': self.read_int16,
            'q': self.read_uint16,
            'i': self.read_int32,
            'u': self.read_uint32,
            'x': self.read_int64,
            't': self.read_uint64,
            'd': self.read_double,
            'h': self.read_uint32,
            'o': self.read_string,
            's': self.read_string,
            'g': self.read_signature,
            'a': self.read_array,
            '(': self.read_struct,
            '{': self.read_dict_entry,
            'v': self.read_variant
        }

    def read(self, n, prefetch=False):
        """
        Read from underlying socket into buffer and advance offset accordingly.

        :arg n:
            Number of bytes to read. If not enough bytes are available in the
            buffer, read more from it.
        :arg prefetch:
            Do not update current offset after reading.

        :returns:
            Previous offset (before reading). To get the actual read bytes,
            use the returned value and self.buf.
        """
        def read_sock(length):
            '''reads from the socket, storing any fds sent and handling errors
            from the read itself'''
            if self.sock is not None:
                unix_fd_list = array.array("i")

                try:
                    msg, ancdata, *_ = self.sock.recvmsg(
                        length, socket.CMSG_LEN(MAX_UNIX_FDS * unix_fd_list.itemsize))
                except BlockingIOError:
                    raise MarshallerStreamEndError()

                for level, type_, data in ancdata:
                    if not (level == socket.SOL_SOCKET and type_ == socket.SCM_RIGHTS):
                        continue
                    unix_fd_list.frombytes(data[:len(data) - (len(data) % unix_fd_list.itemsize)])
                    self.unix_fds.extend(list(unix_fd_list))

                return msg
            else:
                return self.stream.read(length)

        # store previously read data in a buffer so we can resume on socket
        # interruptions
        missing_bytes = n - (len(self.buf) - self.offset)
        if missing_bytes > 0:
            data = read_sock(missing_bytes)
            if data == b'':
                raise EOFError()
            elif data is None:
                raise MarshallerStreamEndError()
            self.buf.extend(data)
            if len(data) != missing_bytes:
                raise MarshallerStreamEndError()
        prev = self.offset
        if not prefetch:
            self.offset += n
        return prev

    @staticmethod
    def _padding(offset, align):
        """
        Get padding bytes to get to the next align bytes mark.

        For any align value, the correct padding formula is:

            (align - (offset % align)) % align

        However, if align is a power of 2 (always the case here), the slow MOD
        operator can be replaced by a bitwise AND:

            (align - (offset & (align - 1))) & (align - 1)

        Which can be simplified to:

            (-offset) & (align - 1)
        """
        return (-offset) & (align - 1)

    def align(self, n):
        padding = self._padding(self.offset, n)
        if padding > 0:
            self.read(padding)

    def read_byte(self, _=None):
        return self.buf[self.read(1)]

    def read_boolean(self, _=None):
        data = self.read_uint32()
        if data:
            return True
        else:
            return False

    def read_int16(self, _=None):
        return self.read_ctype('h', 2)

    def read_uint16(self, _=None):
        return self.read_ctype('H', 2)

    def read_int32(self, _=None):
        return self.read_ctype('i', 4)

    def read_uint32(self, _=None):
        return self.read_ctype('I', 4)

    def read_int64(self, _=None):
        return self.read_ctype('q', 8)

    def read_uint64(self, _=None):
        return self.read_ctype('Q', 8)

    def read_double(self, _=None):
        return self.read_ctype('d', 8)

    def read_ctype(self, fmt, size):
        self.align(size)
        if self.endian == LITTLE_ENDIAN:
            fmt = '<' + fmt
        else:
            fmt = '>' + fmt
        o = self.read(size)
        return unpack_from(fmt, self.buf, o)[0]

    def read_string(self, _=None):
        str_length = self.read_uint32()
        o = self.read(str_length + 1)  # read terminating '\0' byte as well
        # avoid buffer copies when slicing
        str_mem_slice = memoryview(self.buf)[o:o + str_length]
        return decode(str_mem_slice)

    def read_signature(self, _=None):
        signature_len = self.read_byte()
        o = self.read(signature_len + 1)  # read terminating '\0' byte as well
        # avoid buffer copies when slicing
        sig_mem_slice = memoryview(self.buf)[o:o + signature_len]
        return decode(sig_mem_slice)

    def read_variant(self, _=None):
        signature = self.read_signature()
        signature_tree = SignatureTree._get(signature)
        value = self.read_argument(signature_tree.types[0])
        return Variant(signature_tree, value)

    def read_struct(self, type_):
        self.align(8)

        result = []
        for child_type in type_.children:
            result.append(self.read_argument(child_type))

        return result

    def read_dict_entry(self, type_):
        self.align(8)

        key = self.read_argument(type_.children[0])
        value = self.read_argument(type_.children[1])

        return key, value

    def read_array(self, type_):
        self.align(4)
        array_length = self.read_uint32()

        child_type = type_.children[0]
        if child_type.token in 'xtd{(':
            # the first alignment is not included in the array size
            self.align(8)

        beginning_offset = self.offset

        result = None
        if child_type.token == '{':
            result = {}
            while self.offset - beginning_offset < array_length:
                key, value = self.read_dict_entry(child_type)
                result[key] = value
        elif child_type.token == 'y':
            o = self.read(array_length)
            # avoid buffer copies when slicing
            array_mem_slice = memoryview(self.buf)[o:o + array_length]
            result = array_mem_slice.tobytes()
        else:
            result = []
            while self.offset - beginning_offset < array_length:
                result.append(self.read_argument(child_type))

        return result

    def read_argument(self, type_):
        t = type_.token

        if t not in self.readers:
            raise Exception(f'dont know how to read yet: "{t}"')

        return self.readers[t](type_)

    def _unmarshall(self):
        self.offset = 0
        self.read(16, prefetch=True)
        self.endian = self.read_byte()
        if self.endian != LITTLE_ENDIAN and self.endian != BIG_ENDIAN:
            raise InvalidMessageError('Expecting endianness as the first byte')
        message_type = MessageType(self.read_byte())
        flags = MessageFlag(self.read_byte())

        protocol_version = self.read_byte()

        if protocol_version != PROTOCOL_VERSION:
            raise InvalidMessageError(f'got unknown protocol version: {protocol_version}')

        body_len = self.read_uint32()
        serial = self.read_uint32()

        header_len = self.read_uint32()
        msg_len = header_len + self._padding(header_len, 8) + body_len
        self.read(msg_len, prefetch=True)
        # backtrack offset since header array length needs to be read again
        self.offset -= 4

        header_fields = {}
        for field_struct in self.read_argument(SignatureTree._get('a(yv)').types[0]):
            field = HeaderField(field_struct[0])
            header_fields[field.name] = field_struct[1].value

        self.align(8)

        path = header_fields.get(HeaderField.PATH.name)
        interface = header_fields.get(HeaderField.INTERFACE.name)
        member = header_fields.get(HeaderField.MEMBER.name)
        error_name = header_fields.get(HeaderField.ERROR_NAME.name)
        reply_serial = header_fields.get(HeaderField.REPLY_SERIAL.name)
        destination = header_fields.get(HeaderField.DESTINATION.name)
        sender = header_fields.get(HeaderField.SENDER.name)
        signature = header_fields.get(HeaderField.SIGNATURE.name, '')
        signature_tree = SignatureTree._get(signature)
        # unix_fds = header_fields.get(HeaderField.UNIX_FDS.name, 0)

        body = []

        if body_len:
            for type_ in signature_tree.types:
                body.append(self.read_argument(type_))

        self.message = Message(destination=destination,
                               path=path,
                               interface=interface,
                               member=member,
                               message_type=message_type,
                               flags=flags,
                               error_name=error_name,
                               reply_serial=reply_serial,
                               sender=sender,
                               unix_fds=self.unix_fds,
                               signature=signature_tree,
                               body=body,
                               serial=serial)

    def unmarshall(self):
        try:
            self._unmarshall()
            return self.message
        except MarshallerStreamEndError:
            return None

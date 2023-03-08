from .validators import is_object_path_valid
from .errors import InvalidSignatureError, SignatureBodyMismatchError

from typing import Any, List, Union


class SignatureType:
    """A class that represents a single complete type within a signature.

    This class is not meant to be constructed directly. Use the :class:`SignatureTree`
    class to parse signatures.

    :ivar ~.signature: The signature of this complete type.
    :vartype ~.signature: str

    :ivar children: A list of child types if this is a container type. Arrays \
    have one child type, dict entries have two child types (key and value), and \
    structs have child types equal to the number of struct members.
    :vartype children: list(:class:`SignatureType`)
    """
    _tokens = 'ybnqiuxtdsogavh({'

    def __init__(self, token):
        self.token = token
        self.children = []
        self._signature = None

    def __eq__(self, other):
        if type(other) is SignatureType:
            return self.signature == other.signature
        else:
            return super().__eq__(other)

    def _collapse(self):
        if self.token not in 'a({':
            return self.token

        signature = [self.token]

        for child in self.children:
            signature.append(child._collapse())

        if self.token == '(':
            signature.append(')')
        elif self.token == '{':
            signature.append('}')

        return ''.join(signature)

    @property
    def signature(self) -> str:
        if self._signature is not None:
            return self._signature
        self._signature = self._collapse()
        return self._signature

    @staticmethod
    def _parse_next(signature):
        if not signature:
            return (None, '')

        token = signature[0]

        if token not in SignatureType._tokens:
            raise InvalidSignatureError(f'got unexpected token: "{token}"')

        # container types
        if token == 'a':
            self = SignatureType('a')
            (child, signature) = SignatureType._parse_next(signature[1:])
            if not child:
                raise InvalidSignatureError('missing type for array')
            self.children.append(child)
            return (self, signature)
        elif token == '(':
            self = SignatureType('(')
            signature = signature[1:]
            while True:
                (child, signature) = SignatureType._parse_next(signature)
                if not signature:
                    raise InvalidSignatureError('missing closing ")" for struct')
                self.children.append(child)
                if signature[0] == ')':
                    return (self, signature[1:])
        elif token == '{':
            self = SignatureType('{')
            signature = signature[1:]
            (key_child, signature) = SignatureType._parse_next(signature)
            if not key_child or len(key_child.children):
                raise InvalidSignatureError('expected a simple type for dict entry key')
            self.children.append(key_child)
            (value_child, signature) = SignatureType._parse_next(signature)
            if not value_child:
                raise InvalidSignatureError('expected a value for dict entry')
            if not signature or signature[0] != '}':
                raise InvalidSignatureError('missing closing "}" for dict entry')
            self.children.append(value_child)
            return (self, signature[1:])

        # basic type
        return (SignatureType(token), signature[1:])

    def _verify_byte(self, body):
        BYTE_MIN = 0x00
        BYTE_MAX = 0xff
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus BYTE type "y" must be Python type "int", got {type(body)}')
        if body < BYTE_MIN or body > BYTE_MAX:
            raise SignatureBodyMismatchError(
                f'DBus BYTE type must be between {BYTE_MIN} and {BYTE_MAX}')

    def _verify_boolean(self, body):
        if not isinstance(body, bool):
            raise SignatureBodyMismatchError(
                f'DBus BOOLEAN type "b" must be Python type "bool", got {type(body)}')

    def _verify_int16(self, body):
        INT16_MIN = -0x7fff - 1
        INT16_MAX = 0x7fff
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus INT16 type "n" must be Python type "int", got {type(body)}')
        elif body > INT16_MAX or body < INT16_MIN:
            raise SignatureBodyMismatchError(
                f'DBus INT16 type "n" must be between {INT16_MIN} and {INT16_MAX}')

    def _verify_uint16(self, body):
        UINT16_MIN = 0
        UINT16_MAX = 0xffff
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus UINT16 type "q" must be Python type "int", got {type(body)}')
        elif body > UINT16_MAX or body < UINT16_MIN:
            raise SignatureBodyMismatchError(
                f'DBus UINT16 type "q" must be between {UINT16_MIN} and {UINT16_MAX}')

    def _verify_int32(self, body):
        INT32_MIN = -0x7fffffff - 1
        INT32_MAX = 0x7fffffff
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus INT32 type "i" must be Python type "int", got {type(body)}')
        elif body > INT32_MAX or body < INT32_MIN:
            raise SignatureBodyMismatchError(
                f'DBus INT32 type "i" must be between {INT32_MIN} and {INT32_MAX}')

    def _verify_uint32(self, body):
        UINT32_MIN = 0
        UINT32_MAX = 0xffffffff
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus UINT32 type "u" must be Python type "int", got {type(body)}')
        elif body > UINT32_MAX or body < UINT32_MIN:
            raise SignatureBodyMismatchError(
                f'DBus UINT32 type "u" must be between {UINT32_MIN} and {UINT32_MAX}')

    def _verify_int64(self, body):
        INT64_MAX = 9223372036854775807
        INT64_MIN = -INT64_MAX - 1
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus INT64 type "x" must be Python type "int", got {type(body)}')
        elif body > INT64_MAX or body < INT64_MIN:
            raise SignatureBodyMismatchError(
                f'DBus INT64 type "x" must be between {INT64_MIN} and {INT64_MAX}')

    def _verify_uint64(self, body):
        UINT64_MIN = 0
        UINT64_MAX = 18446744073709551615
        if not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus UINT64 type "t" must be Python type "int", got {type(body)}')
        elif body > UINT64_MAX or body < UINT64_MIN:
            raise SignatureBodyMismatchError(
                f'DBus UINT64 type "t" must be between {UINT64_MIN} and {UINT64_MAX}')

    def _verify_double(self, body):
        if not isinstance(body, float) and not isinstance(body, int):
            raise SignatureBodyMismatchError(
                f'DBus DOUBLE type "d" must be Python type "float" or "int", got {type(body)}')

    def _verify_unix_fd(self, body):
        try:
            self._verify_uint32(body)
        except SignatureBodyMismatchError:
            raise SignatureBodyMismatchError('DBus UNIX_FD type "h" must be a valid UINT32')

    def _verify_object_path(self, body):
        if not is_object_path_valid(body):
            raise SignatureBodyMismatchError(
                'DBus OBJECT_PATH type "o" must be a valid object path')

    def _verify_string(self, body):
        if not isinstance(body, str):
            raise SignatureBodyMismatchError(
                f'DBus STRING type "s" must be Python type "str", got {type(body)}')

    def _verify_signature(self, body):
        # I guess we could run it through the SignatureTree parser instead
        if not isinstance(body, str):
            raise SignatureBodyMismatchError(
                f'DBus SIGNATURE type "g" must be Python type "str", got {type(body)}')
        if len(body.encode()) > 0xff:
            raise SignatureBodyMismatchError('DBus SIGNATURE type "g" must be less than 256 bytes')

    def _verify_array(self, body):
        child_type = self.children[0]

        if child_type.token == '{':
            if not isinstance(body, dict):
                raise SignatureBodyMismatchError(
                    f'DBus ARRAY type "a" with DICT_ENTRY child must be Python type "dict", got {type(body)}'
                )
            for key, value in body.items():
                child_type.children[0].verify(key)
                child_type.children[1].verify(value)
        elif child_type.token == 'y':
            if not isinstance(body, bytes):
                raise SignatureBodyMismatchError(
                    f'DBus ARRAY type "a" with BYTE child must be Python type "bytes", got {type(body)}'
                )
                # no need to verify children
        else:
            if not isinstance(body, list):
                raise SignatureBodyMismatchError(
                    f'DBus ARRAY type "a" must be Python type "list", got {type(body)}')
            for member in body:
                child_type.verify(member)

    def _verify_struct(self, body):
        # TODO allow tuples
        if not isinstance(body, list):
            raise SignatureBodyMismatchError(
                f'DBus STRUCT type "(" must be Python type "list", got {type(body)}')

        if len(body) != len(self.children):
            raise SignatureBodyMismatchError(
                'DBus STRUCT type "(" must have Python list members equal to the number of struct type members'
            )

        for i, member in enumerate(body):
            self.children[i].verify(member)

    def _verify_variant(self, body):
        # a variant signature and value is valid by construction
        if not isinstance(body, Variant):
            raise SignatureBodyMismatchError(
                f'DBus VARIANT type "v" must be Python type "Variant", got {type(body)}')

    def verify(self, body: Any) -> bool:
        """Verify that the body matches this type.

        :returns: True if the body matches this type.
        :raises:
            :class:`SignatureBodyMismatchError` if the body does not match this type.
        """
        if body is None:
            raise SignatureBodyMismatchError('Cannot serialize Python type "None"')
        elif self.token == 'y':
            self._verify_byte(body)
        elif self.token == 'b':
            self._verify_boolean(body)
        elif self.token == 'n':
            self._verify_int16(body)
        elif self.token == 'q':
            self._verify_uint16(body)
        elif self.token == 'i':
            self._verify_int32(body)
        elif self.token == 'u':
            self._verify_uint32(body)
        elif self.token == 'x':
            self._verify_int64(body)
        elif self.token == 't':
            self._verify_uint64(body)
        elif self.token == 'd':
            self._verify_double(body)
        elif self.token == 'h':
            self._verify_unix_fd(body)
        elif self.token == 'o':
            self._verify_object_path(body)
        elif self.token == 's':
            self._verify_string(body)
        elif self.token == 'g':
            self._verify_signature(body)
        elif self.token == 'a':
            self._verify_array(body)
        elif self.token == '(':
            self._verify_struct(body)
        elif self.token == 'v':
            self._verify_variant(body)
        else:
            raise Exception(f'cannot verify type with token {self.token}')

        return True


class SignatureTree:
    """A class that represents a signature as a tree structure for conveniently
    working with DBus signatures.

    This class will not normally be used directly by the user.

    :ivar types: A list of parsed complete types.
    :vartype types: list(:class:`SignatureType`)

    :ivar ~.signature: The signature of this signature tree.
    :vartype ~.signature: str

    :raises:
        :class:`InvalidSignatureError` if the given signature is not valid.
    """

    _cache = {}

    @staticmethod
    def _get(signature: str = ''):
        if signature in SignatureTree._cache:
            return SignatureTree._cache[signature]
        SignatureTree._cache[signature] = SignatureTree(signature)
        return SignatureTree._cache[signature]

    def __init__(self, signature: str = ''):
        self.signature = signature

        self.types = []

        if len(signature) > 0xff:
            raise InvalidSignatureError('A signature must be less than 256 characters')

        while signature:
            (type_, signature) = SignatureType._parse_next(signature)
            self.types.append(type_)

    def __eq__(self, other):
        if type(other) is SignatureTree:
            return self.signature == other.signature
        else:
            return super().__eq__(other)

    def verify(self, body: List[Any]):
        """Verifies that the give body matches this signature tree

        :param body: the body to verify for this tree
        :type body: list(Any)

        :returns: True if the signature matches the body or an exception if not.

        :raises:
            :class:`SignatureBodyMismatchError` if the signature does not match the body.
        """
        if not isinstance(body, list):
            raise SignatureBodyMismatchError(f'The body must be a list (got {type(body)})')
        if len(body) != len(self.types):
            raise SignatureBodyMismatchError(
                f'The body has the wrong number of types (got {len(body)}, expected {len(self.types)})'
            )
        for i, type_ in enumerate(self.types):
            type_.verify(body[i])

        return True


class Variant:
    """A class to represent a DBus variant (type "v").

    This class is used in message bodies to represent variants. The user can
    expect a value in the body with type "v" to use this class and can
    construct this class directly for use in message bodies sent over the bus.

    :ivar signature: The signature for this variant. Must be a single complete type.
    :vartype signature: str

    :ivar signature_type: The parsed signature of this variant.
    :vartype signature_type: :class:`SignatureType`

    :ivar value: The value of this variant. Must correspond to the signature.
    :vartype value: Any

    :raises:
        :class:`InvalidSignatureError` if the signature is not valid.
        :class:`SignatureBodyMismatchError` if the signature does not match the body.
    """
    def __init__(self, signature: Union[str, SignatureTree, SignatureType], value: Any):
        signature_str = ''
        signature_tree = None
        signature_type = None

        if type(signature) is SignatureTree:
            signature_tree = signature
        elif type(signature) is SignatureType:
            signature_type = signature
            signature_str = signature.signature
        elif type(signature) is str:
            signature_tree = SignatureTree._get(signature)
        else:
            raise TypeError('signature must be a SignatureTree, SignatureType, or a string')

        if signature_tree:
            if len(signature_tree.types) != 1:
                raise ValueError('variants must have a signature for a single complete type')
            signature_str = signature_tree.signature
            signature_type = signature_tree.types[0]

        signature_type.verify(value)

        self.type = signature_type
        self.signature = signature_str
        self.value = value

    def __eq__(self, other):
        if type(other) is Variant:
            return self.signature == other.signature and self.value == other.value
        else:
            return super().__eq__(other)

    def __repr__(self):
        return "<dbus_next.signature.Variant ('%s', %s)>" % (self.type.signature, self.value)

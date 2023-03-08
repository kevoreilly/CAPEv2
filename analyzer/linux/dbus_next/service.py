from .constants import PropertyAccess
from .signature import SignatureTree, SignatureBodyMismatchError, Variant
from . import introspection as intr
from .errors import SignalDisabledError
from ._private.util import signature_contains_type, replace_fds_with_idx, replace_idx_with_fds, parse_annotation

from functools import wraps
import inspect
from typing import no_type_check_decorator, Dict, List, Any
import copy
import asyncio


class _Method:
    def __init__(self, fn, name, disabled=False):
        in_signature = ''
        out_signature = ''

        inspection = inspect.signature(fn)

        in_args = []
        for i, param in enumerate(inspection.parameters.values()):
            if i == 0:
                # first is self
                continue
            annotation = parse_annotation(param.annotation)
            if not annotation:
                raise ValueError(
                    'method parameters must specify the dbus type string as an annotation')
            in_args.append(intr.Arg(annotation, intr.ArgDirection.IN, param.name))
            in_signature += annotation

        out_args = []
        out_signature = parse_annotation(inspection.return_annotation)
        if out_signature:
            for type_ in SignatureTree._get(out_signature).types:
                out_args.append(intr.Arg(type_, intr.ArgDirection.OUT))

        self.name = name
        self.fn = fn
        self.disabled = disabled
        self.introspection = intr.Method(name, in_args, out_args)
        self.in_signature = in_signature
        self.out_signature = out_signature
        self.in_signature_tree = SignatureTree._get(in_signature)
        self.out_signature_tree = SignatureTree._get(out_signature)


def method(name: str = None, disabled: bool = False):
    """A decorator to mark a class method of a :class:`ServiceInterface` to be a DBus service method.

    The parameters and return value must each be annotated with a signature
    string of a single complete DBus type.

    This class method will be called when a client calls the method on the DBus
    interface. The parameters given to the function come from the calling
    client and will conform to the dbus-next type system. The parameters
    returned will be returned to the calling client and must conform to the
    dbus-next type system. If multiple parameters are returned, they must be
    contained within a :class:`list`.

    The decorated method may raise a :class:`DBusError <dbus_next.DBusError>`
    to return an error to the client.

    :param name: The member name that DBus clients will use to call this method. Defaults to the name of the class method.
    :type name: str
    :param disabled: If set to true, the method will not be visible to clients.
    :type disabled: bool

    :example:

    ::

        @method()
        def echo(self, val: 's') -> 's':
            return val

        @method()
        def echo_two(self, val1: 's', val2: 'u') -> 'su':
            return [val1, val2]
    """
    if name is not None and type(name) is not str:
        raise TypeError('name must be a string')
    if type(disabled) is not bool:
        raise TypeError('disabled must be a bool')

    @no_type_check_decorator
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            fn(*args, **kwargs)

        fn_name = name if name else fn.__name__
        wrapped.__dict__['__DBUS_METHOD'] = _Method(fn, fn_name, disabled=disabled)

        return wrapped

    return decorator


class _Signal:
    def __init__(self, fn, name, disabled=False):
        inspection = inspect.signature(fn)

        args = []
        signature = ''
        signature_tree = None

        return_annotation = parse_annotation(inspection.return_annotation)

        if return_annotation:
            signature = return_annotation
            signature_tree = SignatureTree._get(signature)
            for type_ in signature_tree.types:
                args.append(intr.Arg(type_, intr.ArgDirection.OUT))
        else:
            signature = ''
            signature_tree = SignatureTree._get('')

        self.signature = signature
        self.signature_tree = signature_tree
        self.name = name
        self.disabled = disabled
        self.introspection = intr.Signal(self.name, args)


def signal(name: str = None, disabled: bool = False):
    """A decorator to mark a class method of a :class:`ServiceInterface` to be a DBus signal.

    The signal is broadcast on the bus when the decorated class method is
    called by the user.

    If the signal has an out argument, the class method must have a return type
    annotation with a signature string of a single complete DBus type and the
    return value of the class method must conform to the dbus-next type system.
    If the signal has multiple out arguments, they must be returned within a
    ``list``.

    :param name: The member name that will be used for this signal. Defaults to
        the name of the class method.
    :type name: str
    :param disabled: If set to true, the signal will not be visible to clients.
    :type disabled: bool

    :example:

    ::

        @signal()
        def string_signal(self, val) -> 's':
            return val

        @signal()
        def two_strings_signal(self, val1, val2) -> 'ss':
            return [val1, val2]
    """
    if name is not None and type(name) is not str:
        raise TypeError('name must be a string')
    if type(disabled) is not bool:
        raise TypeError('disabled must be a bool')

    @no_type_check_decorator
    def decorator(fn):
        fn_name = name if name else fn.__name__
        signal = _Signal(fn, fn_name, disabled)

        @wraps(fn)
        def wrapped(self, *args, **kwargs):
            if signal.disabled:
                raise SignalDisabledError('Tried to call a disabled signal')
            result = fn(self, *args, **kwargs)
            ServiceInterface._handle_signal(self, signal, result)
            return result

        wrapped.__dict__['__DBUS_SIGNAL'] = signal

        return wrapped

    return decorator


class _Property(property):
    def set_options(self, options):
        self.options = getattr(self, 'options', {})
        for k, v in options.items():
            self.options[k] = v

        if 'name' in options and options['name'] is not None:
            self.name = options['name']
        else:
            self.name = self.prop_getter.__name__

        if 'access' in options:
            self.access = PropertyAccess(options['access'])
        else:
            self.access = PropertyAccess.READWRITE

        if 'disabled' in options:
            self.disabled = options['disabled']
        else:
            self.disabled = False

        self.introspection = intr.Property(self.name, self.signature, self.access)

        self.__dict__['__DBUS_PROPERTY'] = True

    def __init__(self, fn, *args, **kwargs):
        self.prop_getter = fn
        self.prop_setter = None

        inspection = inspect.signature(fn)
        if len(inspection.parameters) != 1:
            raise ValueError('the property must only have the "self" input parameter')

        return_annotation = parse_annotation(inspection.return_annotation)

        if not return_annotation:
            raise ValueError(
                'the property must specify the dbus type string as a return annotation string')

        self.signature = return_annotation
        tree = SignatureTree._get(return_annotation)

        if len(tree.types) != 1:
            raise ValueError('the property signature must be a single complete type')

        self.type = tree.types[0]

        if 'options' in kwargs:
            options = kwargs['options']
            self.set_options(options)
            del kwargs['options']

        super().__init__(fn, *args, **kwargs)

    def setter(self, fn, **kwargs):
        # XXX The setter decorator seems to be recreating the class in the list
        # of class members and clobbering the options so we need to reset them.
        # Why does it do that?
        result = super().setter(fn, **kwargs)
        result.prop_setter = fn
        result.set_options(self.options)
        return result


def dbus_property(access: PropertyAccess = PropertyAccess.READWRITE,
                  name: str = None,
                  disabled: bool = False):
    """A decorator to mark a class method of a :class:`ServiceInterface` to be a DBus property.

    The class method must be a Python getter method with a return annotation
    that is a signature string of a single complete DBus type. When a client
    gets the property through the ``org.freedesktop.DBus.Properties``
    interface, the getter will be called and the resulting value will be
    returned to the client.

    If the property is writable, it must have a setter method that takes a
    single parameter that is annotated with the same signature. When a client
    sets the property through the ``org.freedesktop.DBus.Properties``
    interface, the setter will be called with the value from the calling
    client.

    The parameters of the getter and the setter must conform to the dbus-next
    type system. The getter or the setter may raise a :class:`DBusError
    <dbus_next.DBusError>` to return an error to the client.

    :param name: The name that DBus clients will use to interact with this
        property on the bus.
    :type name: str
    :param disabled: If set to true, the property will not be visible to
        clients.
    :type disabled: bool

    :example:

    ::

        @dbus_property()
        def string_prop(self) -> 's':
            return self._string_prop

        @string_prop.setter
        def string_prop(self, val: 's'):
            self._string_prop = val
    """
    if type(access) is not PropertyAccess:
        raise TypeError('access must be a PropertyAccess class')
    if name is not None and type(name) is not str:
        raise TypeError('name must be a string')
    if type(disabled) is not bool:
        raise TypeError('disabled must be a bool')

    @no_type_check_decorator
    def decorator(fn):
        options = {'name': name, 'access': access, 'disabled': disabled}
        return _Property(fn, options=options)

    return decorator


class ServiceInterface:
    """An abstract class that can be extended by the user to define DBus services.

    Instances of :class:`ServiceInterface` can be exported on a path of the bus
    with the :class:`export <dbus_next.message_bus.BaseMessageBus.export>`
    method of a :class:`MessageBus <dbus_next.message_bus.BaseMessageBus>`.

    Use the :func:`@method <dbus_next.service.method>`, :func:`@dbus_property
    <dbus_next.service.dbus_property>`, and :func:`@signal
    <dbus_next.service.signal>` decorators to mark class methods as DBus
    methods, properties, and signals respectively.

    :ivar name: The name of this interface as it appears to clients. Must be a
        valid interface name.
    :vartype name: str
    """
    def __init__(self, name: str):
        # TODO cannot be overridden by a dbus member
        self.name = name
        self.__methods = []
        self.__properties = []
        self.__signals = []
        self.__buses = set()

        for name, member in inspect.getmembers(type(self)):
            member_dict = getattr(member, '__dict__', {})
            if type(member) is _Property:
                # XXX The getter and the setter may show up as different
                # members if they have different names. But if they have the
                # same name, they will be the same member. So we try to merge
                # them together here. I wish we could make this cleaner.
                found = False
                for prop in self.__properties:
                    if prop.prop_getter is member.prop_getter:
                        found = True
                        if member.prop_setter is not None:
                            prop.prop_setter = member.prop_setter

                if not found:
                    self.__properties.append(member)
            elif '__DBUS_METHOD' in member_dict:
                method = member_dict['__DBUS_METHOD']
                assert type(method) is _Method
                self.__methods.append(method)
            elif '__DBUS_SIGNAL' in member_dict:
                signal = member_dict['__DBUS_SIGNAL']
                assert type(signal) is _Signal
                self.__signals.append(signal)

        # validate that writable properties have a setter
        for prop in self.__properties:
            if prop.access.writable() and prop.prop_setter is None:
                raise ValueError(f'property "{prop.name}" is writable but does not have a setter')

    def emit_properties_changed(self,
                                changed_properties: Dict[str, Any],
                                invalidated_properties: List[str] = []):
        """Emit the ``org.freedesktop.DBus.Properties.PropertiesChanged`` signal.

        This signal is intended to be used to alert clients when a property of
        the interface has changed.

        :param changed_properties: The keys must be the names of properties exposed by this bus. The values must be valid for the signature of those properties.
        :type changed_properties: dict(str, Any)
        :param invalidated_properties: A list of names of properties that are now invalid (presumably for clients who cache the value).
        :type invalidated_properties: list(str)
        """
        # TODO cannot be overridden by a dbus member
        variant_dict = {}

        for prop in ServiceInterface._get_properties(self):
            if prop.name in changed_properties:
                variant_dict[prop.name] = Variant(prop.signature, changed_properties[prop.name])

        body = [self.name, variant_dict, invalidated_properties]
        for bus in ServiceInterface._get_buses(self):
            bus._interface_signal_notify(self, 'org.freedesktop.DBus.Properties',
                                         'PropertiesChanged', 'sa{sv}as', body)

    def introspect(self) -> intr.Interface:
        """Get introspection information for this interface.

        This might be useful for creating clients for the interface or examining the introspection output of an interface.

        :returns: The introspection data for the interface.
        :rtype: :class:`dbus_next.introspection.Interface`
        """
        # TODO cannot be overridden by a dbus member
        return intr.Interface(self.name,
                              methods=[
                                  method.introspection
                                  for method in ServiceInterface._get_methods(self)
                                  if not method.disabled
                              ],
                              signals=[
                                  signal.introspection
                                  for signal in ServiceInterface._get_signals(self)
                                  if not signal.disabled
                              ],
                              properties=[
                                  prop.introspection
                                  for prop in ServiceInterface._get_properties(self)
                                  if not prop.disabled
                              ])

    @staticmethod
    def _get_properties(interface):
        return interface.__properties

    @staticmethod
    def _get_methods(interface):
        return interface.__methods

    @staticmethod
    def _get_signals(interface):
        return interface.__signals

    @staticmethod
    def _get_buses(interface):
        return interface.__buses

    @staticmethod
    def _add_bus(interface, bus):
        interface.__buses.add(bus)

    @staticmethod
    def _remove_bus(interface, bus):
        interface.__buses.remove(bus)

    @staticmethod
    def _msg_body_to_args(msg):
        if signature_contains_type(msg.signature_tree, msg.body, 'h'):
            # XXX: This deep copy could be expensive if messages are very
            # large. We could optimize this by only copying what we change
            # here.
            return replace_idx_with_fds(msg.signature_tree, copy.deepcopy(msg.body), msg.unix_fds)
        else:
            return msg.body

    @staticmethod
    def _fn_result_to_body(result, signature_tree):
        '''The high level interfaces may return single values which may be
        wrapped in a list to be a message body. Also they may return fds
        directly for type 'h' which need to be put into an external list.'''
        out_len = len(signature_tree.types)
        if result is None:
            result = []
        else:
            if out_len == 1:
                result = [result]
            else:
                if type(result) is not list:
                    raise SignatureBodyMismatchError(
                        'Expected signal to return a list of arguments')

        if out_len != len(result):
            raise SignatureBodyMismatchError(
                f"Signature and function return mismatch, expected {len(signature_tree.types)} arguments but got {len(result)}"
            )

        return replace_fds_with_idx(signature_tree, result)

    @staticmethod
    def _handle_signal(interface, signal, result):
        body, fds = ServiceInterface._fn_result_to_body(result, signal.signature_tree)
        for bus in ServiceInterface._get_buses(interface):
            bus._interface_signal_notify(interface, interface.name, signal.name, signal.signature,
                                         body, fds)

    @staticmethod
    def _get_property_value(interface, prop, callback):
        # XXX MUST CHECK TYPE RETURNED BY GETTER
        try:
            if asyncio.iscoroutinefunction(prop.prop_getter):
                task = asyncio.ensure_future(prop.prop_getter(interface))

                def get_property_callback(task):
                    try:
                        result = task.result()
                    except Exception as e:
                        callback(interface, prop, None, e)
                        return

                    callback(interface, prop, result, None)

                task.add_done_callback(get_property_callback)
                return

            callback(interface, prop, getattr(interface, prop.prop_getter.__name__), None)
        except Exception as e:
            callback(interface, prop, None, e)

    @staticmethod
    def _set_property_value(interface, prop, value, callback):
        # XXX MUST CHECK TYPE TO SET
        try:
            if asyncio.iscoroutinefunction(prop.prop_setter):
                task = asyncio.ensure_future(prop.prop_setter(interface, value))

                def set_property_callback(task):
                    try:
                        task.result()
                    except Exception as e:
                        callback(interface, prop, e)
                        return

                    callback(interface, prop, None)

                task.add_done_callback(set_property_callback)
                return

            setattr(interface, prop.prop_setter.__name__, value)
            callback(interface, prop, None)
        except Exception as e:
            callback(interface, prop, e)

    @staticmethod
    def _get_all_property_values(interface, callback, user_data=None):
        result = {}
        result_error = None

        for prop in ServiceInterface._get_properties(interface):
            if prop.disabled or not prop.access.readable():
                continue
            result[prop.name] = None

        if not result:
            callback(interface, result, user_data, None)
            return

        def get_property_callback(interface, prop, value, e):
            nonlocal result_error
            if e is not None:
                result_error = e
                del result[prop.name]
            else:
                try:
                    result[prop.name] = Variant(prop.signature, value)
                except SignatureBodyMismatchError as e:
                    result_error = e
                    del result[prop.name]

            if any(v is None for v in result.values()):
                return

            callback(interface, result, user_data, result_error)

        for prop in ServiceInterface._get_properties(interface):
            if prop.disabled or not prop.access.readable():
                continue
            ServiceInterface._get_property_value(interface, prop, get_property_callback)

# Original Copyright: 2020, Andrew Blair Schenck
# https://github.com/andrewschenck/paramiko-jump
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# A copy of the License is available at:
# http://www.apache.org/licenses/LICENSE-2.0

"""

Objects provided by this module:

    :class:`SSHJumpClient`
    :class:`DummyAuthHandler`
    :func:`jump_host`
    :func:`simple_auth_handler`

"""

from contextlib import contextmanager
from getpass import getpass
from typing import AnyStr, Callable, List, Optional, Sequence, Tuple, Union

from paramiko import AutoAddPolicy
from paramiko.client import SSH_PORT, SSHClient

_Host = Union[AnyStr, Tuple[AnyStr, int]]
_Prompt = Tuple[AnyStr, bool]


class SSHJumpClient(SSHClient):
    """
    Manage an SSH session which is optionally being proxied
    through a Jump Host.
    """

    def __init__(
        self,
        *,
        jump_session: Optional[SSHClient] = None,
        auth_handler: Optional[Callable] = None,
    ):
        """
        :param jump_session:
            If provided, proxy SSH connections through the another
            instance of SSHClient.
        :param auth_handler:
            If provided, keyboard-interactive authentication will be
            implemented, using this handler as the callback. If this
            is set to None, use Paramiko's default authentication
            algorithm instead of forcing keyboard-interactive
            authentication.
        """
        super().__init__()

        j = self._jump_session = jump_session
        if j is not None and not hasattr(j, "_transport"):
            raise TypeError(f"bad jump_session: {j}")
        self._auth_handler = auth_handler

    def __repr__(self):
        return f"{self.__class__.__name__}(" f"jump_session={self._jump_session!r}, " f"auth_handler={self._auth_handler!r})"

    def __str__(self):
        return self.__class__.__name__

    def _auth(
        self,
        username,
        password,
        pkey,
        key_filenames,
        allow_agent,
        look_for_keys,
        gss_auth,
        gss_kex,
        gss_deleg_creds,
        gss_host,
        passphrase,
    ):  # pylint: disable=R0913
        if callable(self._auth_handler):
            return self._transport.auth_interactive(
                username=username,
                handler=self._auth_handler,
            )

        return super()._auth(
            username=username,
            password=password,
            pkey=pkey,
            key_filenames=key_filenames,
            allow_agent=allow_agent,
            look_for_keys=look_for_keys,
            gss_auth=gss_auth,
            gss_kex=gss_kex,
            gss_deleg_creds=gss_deleg_creds,
            gss_host=gss_host,
            passphrase=passphrase,
        )

    def connect(
        self,
        hostname,
        port=SSH_PORT,
        username=None,
        password=None,
        pkey=None,
        key_filename=None,
        timeout=None,
        allow_agent=True,
        look_for_keys=True,
        compress=False,
        sock=None,
        gss_auth=False,
        gss_kex=False,
        gss_deleg_creds=True,
        gss_host=None,
        banner_timeout=None,
        auth_timeout=None,
        gss_trust_dns=True,
        passphrase=None,
        disabled_algorithms=None,
    ):  # pylint: disable=R0913,R0914
        if self._jump_session is not None:
            if sock is not None:
                raise ValueError("jump_session= and sock= are mutually exclusive")
            transport = self._jump_session._transport  # pylint: disable=W0212
            sock = transport.open_channel(
                kind="direct-tcpip",
                dest_addr=(hostname, port),
                src_addr=transport.getpeername(),
            )

        self.set_missing_host_key_policy(AutoAddPolicy())
        return super().connect(
            hostname=hostname,
            port=port,
            username=username,
            password=password,
            pkey=pkey,
            key_filename=key_filename,
            timeout=timeout,
            allow_agent=allow_agent,
            look_for_keys=look_for_keys,
            compress=compress,
            sock=sock,
            gss_auth=gss_auth,
            gss_kex=gss_kex,
            gss_deleg_creds=gss_deleg_creds,
            gss_host=gss_host,
            banner_timeout=banner_timeout,
            auth_timeout=auth_timeout,
            gss_trust_dns=gss_trust_dns,
            passphrase=passphrase,
            disabled_algorithms=disabled_algorithms,
        )


class DummyAuthHandler:
    """Stateful auth handler for paramiko that will return a list of
     auth parameters for every CLI prompt

    Example
    -------
        >>> from paramiko_jump import DummyAuthHandler
        >>> handler = DummyAuthHandler(['password'], ['1'])
        >>> handler()
        ['password']
        >>> handler()
        ['1']

    """

    def __init__(self, *items):
        self._iterator = iter(items)

    def __call__(self, *args, **kwargs):
        try:
            return next(self)
        except StopIteration:
            return []

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iterator)


@contextmanager
def jump_host(
    hostname: AnyStr,
    username: AnyStr,
    password: AnyStr,
    auth_handler=None,
    look_for_keys=True,
    auto_add_missing_key_policy=True,
):  # pylint: disable=R0913
    """

    Example
    -------
    >>> from paramiko_jump import SSHJumpClient, simple_auth_handler
    >>> with jump_host(
    >>>         hostname='jump-host',
    >>>         username='username') as jump:
    >>>     target = SSHJumpClient(jump_session=jumper)
    >>>     target.connect(hostname='target-host', username='target-user')
    >>>     _, stdout, _ = target.exec_command('sh ver')
    >>>     print(stdout.read().decode())
    >>>     target.close()


    :param hostname:
        The hostname of the jump host.
    :param username:
        The username used to authenticate with the jump host.
    :param password:
        Password used to authenticate with the jump host.
    :param auth_handler:
        If provided, keyboard-interactive authentication will be
        implemented, using this handler as the callback. If this
        is set to None, use Paramiko's default authentication
        algorithm instead of forcing keyboard-interactive
        authentication.
    :param look_for_keys:
        Gives Paramiko permission to look around in our ~/.ssh
        folder to discover SSH keys on its own (Default False)
    :param auto_add_missing_key_policy:
        If set to True, setting the missing host key policy on the jump is set
        to auto add policy. (Default False)
    :return:
        Connected SSHJumpClient
    """
    jumper = SSHJumpClient(auth_handler=auth_handler)
    if auto_add_missing_key_policy:
        jumper.set_missing_host_key_policy(AutoAddPolicy())
    try:
        jumper.connect(
            hostname=hostname,
            username=username,
            password=password,
            look_for_keys=look_for_keys,
            allow_agent=False,
        )
        yield jumper
    finally:
        jumper.close()


def simple_auth_handler(
    title: AnyStr,
    instructions: AnyStr,
    prompt_list: Sequence[_Prompt],
) -> List[AnyStr]:
    """
    Authentication callback, for keyboard-interactive
    authentication.

    :param title:
        Displayed to the end user before anything else.
    :param instructions:
        Displayed to the end user. Typically contains text explaining
        the authentication scheme and / or legal disclaimers.
    :param prompt_list:
        A Sequence of (AnyStr, bool). Each string element is
        displayed as an end-user input prompt. The corresponding
        boolean element indicates whether the user input should
        be 'echoed' back to the terminal during the interaction.
    """
    answers = []
    if title:
        print(title)
    if instructions:
        print(instructions)

    for prompt, show_input in prompt_list:
        input_ = input if show_input else getpass
        answers.append(input_(prompt))
    return answers

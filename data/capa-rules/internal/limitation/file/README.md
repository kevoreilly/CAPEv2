# file limitations

This directory contains rules with the special namespace `internal/limitation/file`.
capa uses these rules to identify files that it cannot handle well, such as .NET modules or packed programs.
When one of these rules matches, capa will render the description as a warning message and bail.
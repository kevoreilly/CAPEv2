Inside this directory, you may create a `conf` directory. Inside that
directory, you may place files whose names are the
same as those found in the top-level `conf` directory and whose contents
override the default settings found in the latter.

In addition, you may create directories under there whose names are the names
of the files in the top-level `conf` directory with a `.d` appended to it (e.g.
`custom/conf/reporting.conf.d/`. Any file in that directory whose name ends in
`.conf` will be read (in lexicographic order). The last value read for a
setting will be used.

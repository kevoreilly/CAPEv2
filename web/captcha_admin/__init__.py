VERSION = (1, 0, 0, 'final', 0)
__author__ = u'Daniel Barreto'
__license__ = u'MIT'
__maintainer__ = u'Micah Mangione'
__email__ = 'micah@connectio.us'
__status__ = 'RC'

def get_version(version=VERSION):
    "Returns a PEP 386-compliant version number from VERSION."
    if version is None:
        return '0.0'
    else:
        assert len(version) == 5
        assert version[3] in ('alpha', 'beta', 'rc', 'final')

    # Now build the two parts of the version number:
    # main = X.Y[.Z]
    # sub = .devN - for pre-alpha releases
    #     | {a|b|c}N - for alpha, beta and rc releases

    parts = 2 if version[2] == 0 else 3
    main = '.'.join(str(x) for x in version[:parts])

    sub = ''
    if version[3] != 'final':
        mapping = {'alpha': 'a', 'beta': 'b', 'rc': 'c'}
        sub = mapping[version[3]] + str(version[4])

    return str(main + sub)

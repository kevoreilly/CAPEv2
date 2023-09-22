import copy


class Dictionary(dict):
    """Cuckoo custom dict."""

    def __deepcopy__(self, memo=None):
        new = self.__class__()
        for key, value in self.items():
            new[key] = copy.deepcopy(value, memo=memo)
        return new

    def __getattr__(self, key):
        return self.get(key)

    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

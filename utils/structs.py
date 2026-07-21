import dataclasses


class Struct:
    """Pack/unpack binary data into dataclasses.

    Subclasses are dataclasses whose field order matches the struct.Struct
    format in the `struct` class attribute.
    """
    struct = None

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if getattr(cls, "struct", None) is None:
            raise ValueError("Class {} doesn't define struct".format(cls.__name__))

    def pack(self):
        return self.struct.pack(*dataclasses.astuple(self))

    @classmethod
    def unpack(cls, data):
        return cls(*cls.struct.unpack(data))

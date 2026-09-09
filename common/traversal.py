"""Finite traversal of directory graphs read from untrusted images."""


class TraversalError(RuntimeError):
    pass


class Traversal:
    MAX_NODES = 1_000_000
    MAX_DEPTH = 128

    def __init__(self):
        self.nodes = 0

    def take(self):
        if self.nodes >= self.MAX_NODES:
            raise TraversalError("Filesystem traversal exceeds the node limit")
        self.nodes += 1

    def enter(self, location, ancestors):
        self.take()
        if location in ancestors:
            raise TraversalError("Cyclic directory reference")
        if len(ancestors) >= self.MAX_DEPTH:
            raise TraversalError("Filesystem traversal exceeds the depth limit")
        return ancestors | {location}

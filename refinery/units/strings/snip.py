#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from .. import arg, Unit


class snip(Unit):
    """
    Snips the input data based on a Python slice expression. For example, the
    initialization `slice 0::1 1::1` would yield a unit that first extracts
    every byte at an even position and then, every byte at an odd position. In
    this case, multiple outputs are produced. The unit can be used in reverse
    mode, in which case the specified ranges are deleted sequentially from the
    input.
    """
    def __init__(self, slices: arg.help('Specify start:stop:step in Python slice syntax.') = [slice(None, None)]):
        super().__init__(slices=slices)

    def reverse(self, data):
        for bounds in self.args.slices:
            del data[bounds]
        return data

    def process(self, data):
        for bounds in self.args.slices:
            yield data[bounds]

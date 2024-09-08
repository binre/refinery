#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from refinery.units.pattern import Arg, RegexUnit
from refinery.lib.argformats import regexp, DelayedBinaryArgument
from refinery.lib.tools import exception_to_string


class loop(RegexUnit):
    """
    Applies a given multibin suffix to the input chunk repeatedly. For example, the following
    command would carve the largest base64-encoded buffer from the input, decode it, and then
    decompress the result 20 times:

        emit data | loop 20 csd[b64]:zl

    Notably, the argument after the count is a suffix, which means that handlers are applied
    from left to right (not from right to left). The loop is aborted and the previous result
    returned if an error occurs while evaluating the suffix, or when the output is empty.
    """

    def __init__(
        self,
        count: Arg.Number(metavar='count', help='The number of repeated applications of the suffix.'),
        suffix: Arg(type=str, help='A multibin expression suffix.'),
        whiLe: Arg('-w', '--while', type=regexp, metavar='RE',
            help='Halt when the given regular expression does not match the data.'),
        until: Arg('-u', '--until', type=regexp, metavar='RE',
            help='Halt when the given regular expression matches the data.'),
        fullmatch=False, multiline=False, ignorecase=False,
    ):
        super().__init__(
            count=count,
            suffix=suffix,
            whiLe=whiLe,
            until=until,
            fullmatch=fullmatch,
            multiline=multiline,
            ignorecase=ignorecase,
        )

    def process(self, data):
        _count = self.args.count
        _width = len(str(_count))
        _while = self._while
        _until = self._until

        for k in range(_count):
            if _while and not _while(data):
                self.log_info(F'step {k:0{_width}}: stopping, while-condition violated')
                break
            if _until and _until(data):
                self.log_info(F'step {k:0{_width}}: stopping, until-condition satisfied')
                break
            try:
                out = DelayedBinaryArgument(
                    self.args.suffix, reverse=True, seed=data)(data)
            except Exception as error:
                msg = exception_to_string(error)
                self.log_info(F'step {k:0{_width}}: stopping after error; {msg}')
                break
            if not out:
                self.log_info(F'step {k:0{_width}}: stopping after empty result')
                break
            data[:] = out

        return data

    @property
    def _while(self):
        return self._make_matcher(self.args.whiLe)

    @property
    def _until(self):
        return self._make_matcher(self.args.until)

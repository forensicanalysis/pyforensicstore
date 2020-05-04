# Copyright (c) 2019 Siemens AG
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
# the Software, and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# Author(s): Jonas Plum
"""
A ForensicStore is a database that can be used to store forensic items and files.

"""
import os


class ForensicStoreResolver:

    def __init__(self, forensicstore, item_type):
        self.forensicstore = forensicstore
        self.scope = [item_type]

    def push_scope(self, scope):
        self.scope.append(scope.replace("jsonlite:", ""))

    def pop_scope(self):
        self.scope.pop()

    def resolve(self, ref):
        if not ref.startswith("#"):
            basename, _ = os.path.splitext(os.path.basename(ref))
            document = self.forensicstore._schema(basename)  # pylint: disable=protected-access
            return ref, document

        # if ref.startswith("jsonlite:"):
        #     document = self.jsonlite._schema(ref.replace("jsonlite:", ""))
        #     return ref, document
        document = self.forensicstore._schema(self.scope[-1])  # pylint: disable=protected-access
        return ref, self.resolve_fragment(document, ref.replace('#', ''))

    @staticmethod
    def resolve_fragment(document, fragment):
        from jsonschema.compat import (Sequence, unquote)
        from jsonschema import (exceptions)

        fragment = fragment.lstrip(u"/")
        parts = unquote(fragment).split(u"/") if fragment else []

        for part in parts:
            part = part.replace(u"~1", u"/").replace(u"~0", u"~")

            if isinstance(document, Sequence):
                # Array indexes should be turned into integers
                try:
                    part = int(part)
                except ValueError:
                    pass
            try:
                document = document[part]
            except (TypeError, LookupError):
                raise exceptions.RefResolutionError(
                    "Unresolvable JSON pointer: %r" % fragment
                )

        return document

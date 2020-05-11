import pytest
from forensicstore.resolver import ForensicStoreResolver
from jsonschema import (exceptions)


class TestForensicStoreResolver:
    def test_resolve_fragment(self):
        doc = ForensicStoreResolver.resolve_fragment({"foo": ["a", "b"]}, "/foo/0")
        assert doc == "a"

    def test_resolve_wrong_fragment(self):
        with pytest.raises(exceptions.RefResolutionError):
            ForensicStoreResolver.resolve_fragment({"foo": ["a", "b"]}, "/foo/2")

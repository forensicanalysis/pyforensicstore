import unittest

from fs.test import FSTestCases

from forensicstore.sqlitefs import SQLiteFS


class TestSQLiteFS(FSTestCases, unittest.TestCase):

    def make_fs(self):
        sfs = SQLiteFS(":memory:")
        return sfs

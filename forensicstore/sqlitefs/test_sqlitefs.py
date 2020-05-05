import unittest

from fs.test import FSTestCases

from .sqlitefs import SQLiteFS


class TestSQLiteFS(FSTestCases, unittest.TestCase):

    def make_fs(self):
        sfs = SQLiteFS(":memory:")
        return sfs

    def destroy_fs(self, fs):
        fs.close()

# Copyright (c) 2020 Siemens AG
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

import io
import os
import sqlite3
import zlib
from datetime import datetime
from types import TracebackType
from typing import Text, Optional, Any, List, BinaryIO, Type, Iterator, AnyStr, Iterable

from fs import ResourceType, errors
from fs.base import FS
from fs.info import Info
from fs.mode import Mode
from fs.path import basename, dirname
from fs.permissions import Permissions
from fs.subfs import SubFS


class SQLiteFS(FS):
    def __init__(self, url: Text = "", connection: sqlite3.Connection = None):
        super().__init__()

        if (url == "" and connection is None) or (url != "" and connection is not None):
            raise ValueError("need either url or sqlite3Connection")

        self._closed = False
        if url != "":
            self.connection = sqlite3.connect(url, timeout=1.0)
            self.connection.row_factory = sqlite3.Row
        if connection is not None:
            self.connection = connection

        self._meta["invalid_path_chars"] = "\0"
        self._meta["case_insensitive"] = False
        self._meta["unicode_paths"] = True

        cursor = self.connection.cursor()
        cursor.execute("""CREATE TABLE IF NOT EXISTS sqlar(
        name TEXT PRIMARY KEY,  -- name of the file
        mode INT,               -- access permissions
        mtime INT,              -- last modification time
        sz INT,                 -- original file size
        data BLOB               -- compressed content
        );""")
        # create root dir
        if not self.exists("/"):
            cursor.execute(
                "INSERT INTO sqlar (name, mode, mtime, sz, data) VALUES (?, ?, ?, ?, ?)",
                ("/", 0o755, datetime.utcnow().timestamp(), 0, None)
            )
        cursor.close()

    def normalize_path(self, path: Text):
        return self.validatepath(path)

    def _get_row(self, path: Text):
        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT name, mode, mtime, sz, CASE WHEN data IS NULL THEN 'TRUE' ELSE 'FALSE' END dataNull "
            "FROM sqlar "
            "WHERE name = ?",
            (path,)
        )
        result = cursor.fetchone()
        cursor.close()

        return result

    def exists(self, path):  # type: (Text) -> bool
        path = self.normalize_path(path)
        return self._get_row(path) is not None

    def getinfo(self, path: Text, namespaces=None) -> Info:  # namespaces: Optional[Collection[Text]]
        """Get info regarding a file or directory."""
        npath = self.normalize_path(path)
        result = self._get_row(npath)
        if result is None:
            raise errors.ResourceNotFound(path)

        size = result["sz"]
        is_dir = size == 0 and result["dataNull"] == "TRUE"
        raw_info = {
            "basic": {
                "name": basename(result["name"]) if npath != "/" else "",
                "is_dir": is_dir
            },
            "details": {
                "accessed": None,
                "created": None,
                "metadata_changed": None,
                "modified": result["mtime"],
                "size": size,
                "type": ResourceType.directory if is_dir else ResourceType.file,
            }
        }
        return Info(raw_info)

    def listdir(self, path: Text) -> List[Text]:
        """ Get a list of resources in a directory. """
        npath = self.normalize_path(path)
        if not self.exists(npath):
            raise errors.ResourceNotFound(path)
        if not self.isdir(npath):
            raise errors.DirectoryExpected(path)

        qpath = npath + "/%"
        if npath == "/":
            qpath = "/%"

        cursor = self.connection.cursor()
        cursor.execute(
            "SELECT name FROM sqlar WHERE name LIKE ?",
            (qpath,)
        )
        rows = list(cursor.fetchall())
        cursor.close()

        children = []
        for row in rows:
            if row['name'] == npath or "/" in row['name'][len(npath):].strip("/"):
                continue
            children.append(basename(row['name']))

        return children

    def makedir(self, path: Text, permissions: Optional[Permissions] = None, recreate: bool = False) -> SubFS[FS]:
        """ Make a directory. """
        npath = self.normalize_path(path)
        if self.exists(npath):
            if recreate:
                return SubFS(self, npath)
            raise errors.DirectoryExists(path)
        if npath == "/":
            return SubFS(self, path)
        if not self.exists(dirname(npath)):
            raise errors.ResourceNotFound(dirname(path))

        perm = 0o750
        if permissions is not None:
            perm = permissions.mode

        cursor = self.connection.cursor()
        cursor.execute(
            "INSERT INTO sqlar (name, mode, mtime, sz, data) VALUES (?, ?, ?, ?, ?)",
            (npath, perm, datetime.utcnow().timestamp(), 0, None)
        )
        cursor.close()

        return SubFS(self, npath)

    def openbin(self, path: Text, mode: Text = "r", buffering: int = -1, **options: Any) -> BinaryIO:
        """ Open a binary file. """
        npath = self.normalize_path(path)
        if self._closed:
            raise errors.FilesystemClosed

        if not self.exists(dirname(npath)):
            raise errors.ResourceNotFound(dirname(path))

        if "t" in mode:
            raise ValueError
        if "b" not in mode:
            mode += "b"
        file_mode = Mode(mode)

        exists = self.exists(npath)
        if file_mode.exclusive and exists:
            raise errors.FileExists(path)
        if file_mode.reading and not exists:
            raise errors.ResourceNotFound(path)
        if (file_mode.reading or (file_mode.writing and exists)) and self.isdir(path):
            raise errors.FileExpected(path)

        deflate_compress = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        data = deflate_compress.compress(b"") + deflate_compress.flush()
        if file_mode.create and not exists:
            cursor = self.connection.cursor()
            cursor.execute(
                "INSERT INTO sqlar (name, mode, mtime, sz, data) VALUES (?, ?, ?, ?, ?)",
                (npath, 0o700, datetime.utcnow().timestamp(), 0, data)
            )
            cursor.close()
        elif file_mode.truncate:
            cursor = self.connection.cursor()
            cursor.execute("UPDATE sqlar SET data = ? WHERE name = ?", (data, npath))
            cursor.close()

        return SQLiteFile(self, npath, file_mode)

    def remove(self, path: Text) -> None:
        """ Remove a file. """
        npath = self.normalize_path(path)
        if not self.exists(npath):
            raise errors.ResourceNotFound(path)
        if self.isdir(npath):
            raise errors.FileExpected(path)

        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM sqlar WHERE name = ?", (npath,))
        cursor.close()

    def removedir(self, path: Text) -> None:
        """ Remove a directory. """
        npath = self.normalize_path(path)
        if npath == "/":
            raise errors.RemoveRootError
        if not self.exists(npath):
            raise errors.ResourceNotFound(path)
        if not self.isdir(npath):
            raise errors.DirectoryExpected(path)
        if self.listdir(npath):
            raise errors.DirectoryNotEmpty(path)

        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM sqlar WHERE name LIKE ?", (npath,))
        cursor.close()

    def setinfo(self, path: Text, info: Info) -> None:
        """ Set resource information. """
        path = self.normalize_path(path)
        if not self.exists(path):
            raise errors.ResourceNotFound(path)

        perm = None
        if "permissions" in info:
            perm = info['permissions'].mode
        mtime = None
        if "modified" in info:
            mtime = info['modified'].timestamp()
        size = None
        if "size" in info:
            size = info["size"]

        cursor = self.connection.cursor()
        cursor.execute(
            "UPDATE sqlar  SET mode = ?, mtime = ?, sz = ? "
            "WHERE name LIKE ?",
            (perm, mtime, size, path)
        )
        cursor.close()

    def isclosed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """
        Save ForensicStore to its location.
        """
        if self._closed:
            return
        self._closed = True
        self.connection.commit()
        self.connection.close()


class SQLiteFile(io.RawIOBase):

    def __init__(self, fs: SQLiteFS, path: Text, file_mode: Mode):
        super().__init__()
        self.fs = fs
        self.path = path
        self._mode = file_mode

        cursor = self.fs.connection.cursor()
        cursor.execute("SELECT data FROM sqlar WHERE name = ?", (path,))
        result = cursor.fetchone()
        cursor.close()

        if result is not None:
            self.data = io.BytesIO(zlib.decompress(result['data'], -zlib.MAX_WBITS))
            if file_mode.appending:
                self.data.seek(0, 2)
        else:
            self.data = io.BytesIO()
        self._closed = False

    def close(self) -> None:
        self._closed = True
        self.flush()

    def fileno(self) -> int:
        return self.data.fileno()

    def flush(self) -> None:
        if not self._mode.writing:
            return
        self.data.seek(0)
        raw = self.data.read()
        deflate_compress = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
        data = deflate_compress.compress(raw) + deflate_compress.flush()

        cursor = self.fs.connection.cursor()
        cursor.execute("UPDATE sqlar SET data = ?, sz = ? WHERE name = ?", (data, len(raw), self.path))
        cursor.close()

    def isatty(self) -> bool:
        return self.data.isatty()

    def read(self, count: int = -1) -> AnyStr:
        if not self.readable():
            raise IOError
        return self.data.read(count)

    def readable(self) -> bool:
        return self._mode.reading

    def readline(self, limit: int = -1) -> AnyStr:
        if not self.readable():
            raise IOError
        return self.data.readline(limit)

    def readlines(self, hint: int = -1) -> List[AnyStr]:
        if not self.readable():
            raise IOError
        return self.data.readlines(hint)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        return self.data.seek(offset, whence)

    def seekable(self) -> bool:
        return self.data.seekable()

    def tell(self) -> int:
        return self.data.tell()

    def truncate(self, size: Optional[int] = None) -> int:
        new_size = self.data.truncate(size)
        if size is not None and self.data.tell() < size:
            file_size = self.data.seek(0, os.SEEK_END)
            self.data.write(b"\0" * (size - file_size))
            self.data.seek(-size + file_size, os.SEEK_END)  # pylint: disable=invalid-unary-operand-type
        return size or new_size

    def write(self, data: AnyStr) -> int:
        if not self.writable():
            raise IOError
        i = self.data.write(data)
        return i

    def writable(self) -> bool:
        return self._mode.writing

    def writelines(self, lines: Iterable[AnyStr]) -> None:
        if not self.writable():
            raise IOError
        return self.data.writelines(lines)

    def __next__(self) -> AnyStr:
        return self.data.__next__()

    def __iter__(self) -> Iterator[AnyStr]:
        return self.data.__iter__()

    def __enter__(self) -> BinaryIO:
        return self

    def __exit__(self, t: Optional[Type[BaseException]], value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> Optional[bool]:
        self.close()

    @property
    def closed(self):
        return self._closed

    @property
    def name(self):
        return basename(self.path)

    @property
    def mode(self):
        return str(self._mode)

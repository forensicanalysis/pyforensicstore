import io
import sqlite3
from datetime import datetime
from types import TracebackType
from typing import Text, Optional, Any, Collection, List, BinaryIO, Type, Iterator, AnyStr, Iterable

import six
from fs import ResourceType, errors
from fs.base import FS
from fs.info import Info
from fs.mode import Mode
from fs.path import basename
from fs.permissions import Permissions
from fs.subfs import SubFS

table = """CREATE TABLE IF NOT EXISTS sqlar(
    name TEXT PRIMARY KEY,  -- name of the file
mode INT,               -- access permissions
mtime INT,              -- last modification time
sz INT,                 -- original file size
data BLOB               -- compressed content
);"""


class SQLiteFS(FS):
    def __init__(self, url: Text):
        super().__init__()

        self.url = url
        self._closed = False
        self.connection = sqlite3.connect(url, timeout=1.0)
        self.connection.row_factory = sqlite3.Row

        cursor = self.connection.cursor()
        cursor.execute(table)
        cursor.close()

        self.makedir("/", Permissions(mode=0o755))

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
        path = self._normalize_path(path)
        return self._get_row(path) is not None

    def getinfo(self, path: Text, namespaces: Optional[Collection[Text]] = None) -> Info:
        """Get info regarding a file or directory."""
        path = self._normalize_path(path)
        result = self._get_row(path)
        if result is None:
            raise errors.ResourceNotFound(path)
            print("get", result['data'])

        size = result["sz"]
        raw_info = {
            "basic": {
                "name": result["name"] if path != "/" else "",
                "is_dir": size == 0 and result["dataNull"] == "TRUE",
            },
            "details": {
                "accessed": None,
                "created": None,
                "metadata_changed": None,
                "modified": result["mtime"],
                "size": size,
                "type": ResourceType.file,
            }
        }

        return Info(raw_info)

    def listdir(self, path: Text) -> List[Text]:
        """ Get a list of resources in a directory. """
        path = self._normalize_path(path)
        if not self.exists(path):
            raise errors.ResourceNotFound(path)

        cursor = self.connection.cursor()

        qpath = path + "/%"
        if path == "/":
            qpath = "/%"

        cursor.execute(
            "SELECT name FROM sqlar WHERE name LIKE ?",
            (qpath,)
        )
        children = []
        for row in cursor.fetchall():
            if "/" in row['name'][len(path):].strip("/"):
                continue
            children.append(basename(row['name']))
        cursor.close()

        return children

    def _normalize_path(self, path: Text):
        if path == "":
            return "/"
        return "/" + path.lstrip("/")

    def makedir(self, path: Text, permissions: Optional[Permissions] = None, recreate: bool = False) -> SubFS[FS]:
        """ Make a directory. """
        path = self._normalize_path(path)
        if self.exists(path) and not recreate:
            raise errors.DirectoryExists(path)

        cursor = self.connection.cursor()
        try:
            perm = 0o750
            if permissions is not None:
                perm = permissions.mode
            cursor.execute(
                "INSERT INTO sqlar (name, mode, mtime, sz, data) VALUES (?, ?, ?, ?, ?)",
                (path, perm, datetime.utcnow().timestamp(), 0, None)
            )
        except sqlite3.IntegrityError as e:
            if "UNIQUE constraint failed" in str(e) and recreate:
                pass
            else:
                raise e
        except Exception as e:
            raise e
        finally:
            cursor.close()

        return SubFS(self, path)

    def openbin(self, path: Text, mode: Text = "r", buffering: int = -1, **options: Any) -> BinaryIO:
        """ Open a binary file. """
        path = self._normalize_path(path)
        if self._closed:
            raise errors.FilesystemClosed

        m = Mode(mode)

        if m.reading:
            cursor = self.connection.cursor()
            cursor.execute(
                "SELECT rowid, mode, mtime, sz, CASE WHEN data IS NULL THEN 'TRUE' ELSE 'FALSE' END dataNull "
                "FROM sqlar "
                "WHERE name = ?",
                (path,)
            )
            result = cursor.fetchone()
            if result is None:
                six.raise_from(errors.ResourceNotFound(path), None)

            if result["sz"] == 0 and result["dataNull"] == "TRUE":
                raise errors.FileExpected(path)

            cursor.close()

        if m.create and not self.exists(path):
            cursor = self.connection.cursor()
            cursor.execute(
                "INSERT INTO sqlar (name, mode, mtime, sz, data) VALUES (?, ?, ?, ?, ?)",
                (path, 0o700, datetime.utcnow().timestamp(), 0, b"")
            )
            cursor.close()

        if m.truncate:
            cursor = self.connection.cursor()
            cursor.execute("UPDATE sqlar SET data = NULL")
            cursor.close()

        return SQLiteFile(self, path, m)

    def remove(self, path: Text) -> None:
        """ Remove a file. """
        path = self._normalize_path(path)
        if not self.exists(path):
            raise errors.ResourceNotFound(path)
        if self.isdir(path):
            raise errors.FileExpected(path)

        cursor = self.connection.cursor()
        cursor.execute("DELETE FROM sqlar WHERE name = ?", (path,))
        cursor.close()

    def removedir(self, path: Text) -> None:
        path = self._normalize_path(path)
        """ Remove a directory. """
        if path == "/":
            raise errors.RemoveRootError
        if not self.exists(path):
            raise errors.ResourceNotFound(path)
        if not self.isdir(path):
            raise errors.DirectoryExpected(path)
        if len(self.listdir(path)) > 0:
            raise errors.DirectoryNotEmpty(path)

        qpath = path.strip("/") + "/%"
        if path == "/":
            qpath = "/%"

        if not self.exists(path):
            raise errors.ResourceNotFound(path)

        cursor = self.connection.cursor()
        if path != "/":
            cursor.execute("DELETE FROM sqlar WHERE name LIKE ?", (path,))
        cursor.execute("DELETE FROM sqlar WHERE name LIKE ?", (qpath,))
        cursor.close()

    def setinfo(self, path: Text, info: Info) -> None:
        """ Set resource information. """
        path = self._normalize_path(path)
        if not self.exists(path):
            raise errors.ResourceNotFound(path)

        cursor = self.connection.cursor()
        try:
            perm = None
            if "permissions" in info:
                perm = info['permissions'].mode
            mtime = None
            if "modified" in info:
                mtime = info['modified'].timestamp()
            size = None
            if "size" in info:
                size = info["size"]
            cursor.execute(
                "UPDATE sqlar  SET mode = ?, mtime = ?, sz = ? "
                "WHERE name LIKE ?",
                (perm, mtime, size, path)

            )
        except Exception as e:
            raise e
        finally:
            cursor.close()

    def isclosed(self) -> bool:
        return self._closed

    def close(self) -> None:
        """
        Save ForensicStore to its location.
        """
        if self._closed:
            return
            # raise errors.FilesystemClosed

        self._closed = True
        self.connection.commit()
        self.connection.close()


class SQLiteFile(BinaryIO):

    def __init__(self, fs: SQLiteFS, path: Text, mode: Mode):
        super().__init__()
        self.fs = fs
        self.path = path
        self._readable = mode.reading
        self._writeable = mode.writing

        cursor = self.fs.connection.cursor()
        cursor.execute("SELECT data FROM sqlar WHERE name = ?", (path,))

        result = cursor.fetchone()
        if result is not None:
            self.data = io.BytesIO(result['data'])
            if mode.appending:
                self.data.seek(0, 2)
        else:
            self.data = io.BytesIO()

        cursor.close()

    def close(self) -> None:
        self.flush()

    def fileno(self) -> int:
        return self.data.fileno()

    def flush(self) -> None:
        cursor = self.fs.connection.cursor()
        d = self.data.getvalue()
        cursor.execute("UPDATE sqlar SET data = ?, sz = ? WHERE name = ?", (d, len(d), self.path))
        cursor.close()

    def isatty(self) -> bool:
        return self.data.isatty()

    def read(self, n: int = -1) -> AnyStr:
        d = self.data.read(n)
        return d

    def readable(self) -> bool:
        return self._readable

    def readline(self, limit: int = -1) -> AnyStr:
        return self.data.readline()

    def readlines(self, hint: int = -1) -> List[AnyStr]:
        return self.data.readlines()

    def seek(self, offset: int, whence: int = 0) -> int:
        return self.data.seek(offset, whence)

    def seekable(self) -> bool:
        return self.data.seekable()

    def tell(self) -> int:
        return self.data.tell()

    def truncate(self, size: Optional[int] = None) -> int:
        return self.data.truncate(size)

    def write(self, s: AnyStr) -> int:
        i = self.data.write(s)
        return i

    def writable(self) -> bool:
        return self._writeable

    def writelines(self, lines: Iterable[AnyStr]) -> None:
        return self.data.writelines(lines)

    def __next__(self) -> AnyStr:
        return self.data.__next__()

    def __iter__(self) -> Iterator[AnyStr]:
        return self.data.__iter__()

    def __enter__(self) -> BinaryIO:
        return self.data.__enter__()

    def __exit__(self, t: Optional[Type[BaseException]], value: Optional[BaseException],
                 traceback: Optional[TracebackType]) -> Optional[bool]:
        self.flush()


def main():
    fs = SQLiteFS("test.db")
    fs.makedir("/foo")
    print(fs.listdir("/"))


if __name__ == '__main__':
    main()

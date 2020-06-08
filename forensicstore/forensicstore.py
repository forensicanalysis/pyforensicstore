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
JSONLite is a database that can be used to store elements and files.

"""

import hashlib
import json
import logging
import os
import platform
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Union

import flatten_json
import fs
import fs.base
import fs.errors
import fs.osfs
import fs.path
import jsonschema
import pkg_resources
from fs.osfs import OSFS

from .hashed_file import HashedFile
from .resolver import ForensicStoreResolver
from .sqlitefs import SQLiteFS

LOGGER = logging.getLogger(__name__)

DISCRIMINATOR = "type"


class StoreExitsError(Exception):
    pass


class StoreNotExitsError(Exception):
    pass


ELEMENTARY_APPLICATION_ID = 0x656c656d
ELEMENTARY_APPLICATION_ID_DIR_FS = 0x656c7a70
USER_VERSION = 2


class ForensicStore:
    """
    ForensicStore is a class to database that can be used to store forensic elements and files.

    :param str url: Location of the database. Needs to be a path or a valid pyfilesystem2 url
    """

    def __init__(self, url: str, create: bool, application_id: int = ELEMENTARY_APPLICATION_ID):

        if sys.version_info.major != 3:
            raise NotImplementedError("forensicstore requires python 3")
        if platform.system() == "Windows" and sys.version_info.minor < 9:
            raise NotImplementedError("forensicstore requires python 3.9 on windows")

        if isinstance(url, str):
            if not url.endswith(".forensicstore"):
                raise TypeError("File needs to end with '.forensicstore'")
            exists = os.path.exists(url)
            if exists and create:
                raise StoreExitsError
            if not create and not exists:
                raise StoreNotExitsError
            if url[-1] == "/":
                url = url[:-1]

        self.connection = sqlite3.connect(url)  # self.db.connection()
        # self.connection = sqlite3.connect(remote_url, timeout=1.0)
        self.connection.row_factory = sqlite3.Row

        cur = self.connection.cursor()
        cur.execute("CREATE VIRTUAL TABLE IF NOT EXISTS `elements` USING "
                    "fts5(id UNINDEXED, json, insert_time UNINDEXED, "
                    "tokenize=\"unicode61 tokenchars '/.'\")")
        if create:
            cur.execute("PRAGMA application_id = %d" % application_id)
            cur.execute("PRAGMA user_version = %d" % USER_VERSION)
        else:
            cur.execute("PRAGMA application_id")
            application_id = cur.fetchone()["application_id"]
            if application_id not in [ELEMENTARY_APPLICATION_ID, ELEMENTARY_APPLICATION_ID_DIR_FS]:
                raise ValueError("wrong file format (application_id is %d)" % application_id)
            cur.execute("PRAGMA user_version")
            user_version = cur.fetchone()["user_version"]
            if user_version != USER_VERSION:
                raise ValueError(
                    "wrong file format "
                    "(user_version is %d, requires %d)" % (user_version, USER_VERSION)
                )
        cur.close()

        if application_id == ELEMENTARY_APPLICATION_ID_DIR_FS:
            self.fs = OSFS(fs.path.splitext(url)[0])
        else:
            self.fs = SQLiteFS(connection=self.connection)

        self._updated = False
        self._tables = self._get_tables()
        self._schemas = dict()
        self._name_title = dict()
        for entry_point in pkg_resources.iter_entry_points('forensicstore_schemas'):
            schema = entry_point.load()
            self._set_schema(entry_point.name, schema)
            self._name_title[os.path.basename(schema['$id'])] = schema['title']

    ################################
    #   API
    ################################

    def insert(self, element: dict) -> str:
        """
        Insert a single element into the store

        :param dict element: New element
        :return: ID if the inserted element
        :rtype: int
        """
        if DISCRIMINATOR not in element:
            raise KeyError("Missing discriminator %s in element" % DISCRIMINATOR)
        # add uuid
        if 'id' not in element:
            element['id'] = element[DISCRIMINATOR] + '--' + str(uuid.uuid4())

        # discard empty values
        element = {k: v for k, v in element.items() if v is not None and not (isinstance(v, list) and not v)}

        validation_errors = self.validate_element_schema(element)
        if validation_errors:
            raise TypeError("element could not be validated", validation_errors)

        self.update_views(element[DISCRIMINATOR], element)

        # insert element
        cur = self.connection.cursor()
        query = "INSERT INTO elements (id, json, insert_time) VALUES (?, ?, ?)"
        LOGGER.debug("insert query: %s", query)
        try:
            now = datetime.utcnow().isoformat(timespec='milliseconds') + 'Z'
            cur.execute(query, (element['id'], json.dumps(element), now))
        except sqlite3.InterfaceError as error:
            raise error
        finally:
            cur.close()

        return element['id']

    def update_views(self, name: str, element: dict):
        if name not in self._tables:
            self._tables[name] = set()
            self._updated = True
        for field in element.keys():
            if field not in self._tables[name]:
                self._tables[name].add(field)
                self._updated = True

    def get(self, element_id: str) -> dict:
        """
        Get a single element by the element_id

        :param str element_id: ID of the element
        :return: Single element
        :rtype: dict
        """
        cur = self.connection.cursor()

        try:
            cur.execute("SELECT json FROM elements WHERE id=?", (element_id,))
            result = cur.fetchone()
            if not result:
                raise KeyError("element does not exist")

            return self._row_to_element(result)
        except sqlite3.OperationalError as error:
            raise KeyError(error)
        finally:
            cur.close()

    def query(self, query: str) -> []:
        cur = self.connection.cursor()
        cur.execute(query)
        for row in cur.fetchall():
            yield self._row_to_element(row)
        cur.close()

    def update(self, element_id: str, partial_element: dict) -> str:
        """
        Update a single element

        :param str element_id: ID of the element
        :param dict partial_element: Changes for the element
        """
        cur = self.connection.cursor()

        updated_element = self.get(element_id)
        updated_element.update(partial_element)

        self.update_views(updated_element[DISCRIMINATOR], updated_element)

        query = "UPDATE elements SET json=? WHERE id=?"
        cur.execute(query, (json.dumps(updated_element), element_id))
        cur.close()

        return element_id

    def import_forensicstore(self, url: str):
        """
        Import forensicstore file

        :param str url: Location of the observed data file. Needs to be a path or a valid pyfilesystem2 url
        """
        import_db = open(url)
        for element in import_db.all():
            self._import_file(import_db.fs, element)

    def _import_file(self, file_system, element: dict):
        for field in element:
            if field.endswith("_path"):
                with self.store_file(element[field]) as (file_path, file):
                    file.write(file_system.readbytes(element[field]))
                element.update({field: file_path})
        self.insert(element)

    @contextmanager
    def store_file(self, file_path: str) -> (str, HashedFile):
        """
        Creates a writeable context for the contents of the file.

        :param str file_path: Relative location of the new file
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        self.fs.makedirs(fs.path.dirname(file_path), recreate=True)
        i = 0
        base_path, ext = fs.path.splitext(file_path)
        while self.fs.exists(file_path):
            file_path = "%s_%d%s" % (base_path, i, ext)
            i += 1

        the_file = HashedFile(file_path, self.fs)
        yield file_path, the_file
        the_file.close()

    @contextmanager
    def load_file(self, file_path: str):
        the_file = self.fs.open(file_path, "rb")
        yield the_file
        the_file.close()

    def close(self):
        """
        Save ForensicStore to its location.
        """
        if self._updated:
            self.create_views()
        self.fs.close()
        # self.connection.commit()
        # self.connection.close()

    def create_views(self):
        cur = self.connection.cursor()
        for name, fields in self._tables.items():
            cur.execute("DROP VIEW IF EXISTS '%s'" % name)
            columns = []
            for field in fields:
                columns.append("json_extract(json, '$.%s') as '%s'" % (field, field))

            query = "CREATE VIEW '%s' AS SELECT " \
                    "%s FROM elements " \
                    "WHERE json_extract(json, '$.%s') = '%s'" % (name, ",".join(columns), DISCRIMINATOR, name)

            cur.execute(query)
        cur.close()

    ################################
    #   Validate
    ################################

    def validate(self):
        validation_errors = []
        expected_files = set()

        for element in self.all():
            # validate element
            element_errors, element_expected_files = self.validate_element(element)
            validation_errors.extend(element_errors)
            expected_files |= element_expected_files

        stored_files = set(self.fs.walk.files())

        if expected_files - stored_files:
            validation_errors.append("missing files: ('%s')" % "', '".join(expected_files - stored_files))
        if stored_files - expected_files:
            validation_errors.append("additional files: ('%s')" % "', '".join(stored_files - expected_files))

        return validation_errors

    def validate_element(self, element: dict):
        """
        Validate a single element

        :param dict element: element for validation
        :raises TypeError: If element is invalid
        """
        validation_errors = []
        expected_files = set()

        if DISCRIMINATOR not in element:
            validation_errors.append("element needs to have a discriminator, got %s" % element)

        validation_errors += self.validate_element_schema(element)

        # collect export paths
        for field in element.keys():
            if field.endswith("_path"):
                export_path = element[field]

                # validate parent paths
                if '..' in export_path:
                    validation_errors.append("'..' in %s" % export_path)
                    continue

                expected_files.add('/' + export_path)

                # validate existence, is validated later as well
                if not self.fs.exists(element[field]):
                    continue

                # validate size
                if "size" in element:
                    if element["size"] != self.fs.getsize(export_path):
                        validation_errors.append("wrong size for %s" % export_path)

                if "hashes" in element:
                    for hash_algorithm_name, value in element["hashes"].items():
                        if hash_algorithm_name == "MD5":
                            hash_algorithm = hashlib.md5()
                        elif hash_algorithm_name == "SHA-1":
                            hash_algorithm = hashlib.sha1()
                        else:
                            validation_errors.append("unsupported hash %s for %s" % (hash_algorithm_name, export_path))
                            continue
                        hash_algorithm.update(self.fs.readbytes(export_path))
                        if hash_algorithm.hexdigest() != value:
                            validation_errors.append(
                                "hashvalue mismatch %s for %s" % (hash_algorithm_name, export_path)
                            )

        return validation_errors, expected_files

    def validate_element_schema(self, element: dict):
        validation_errors = []

        element_type = element[DISCRIMINATOR]
        schema = self._schema(element_type)
        if schema is None:
            return validation_errors

        try:
            jsonschema.validate(element, schema, resolver=ForensicStoreResolver(self, element_type))
        except jsonschema.ValidationError as error:
            validation_errors.append("element could not be validated, %s" % str(error))
        return validation_errors

    def select(self, conditions=None) -> []:
        """
        Select elements from the ForensicStore

        :param [dict] conditions: List of key values pairs. elements matching any list element are returned
        :return: element generator with the results
        :rtype: [dict]
        """
        if conditions is None:
            conditions = []

        # query db
        ors = []
        for condition in conditions:
            ands = []
            for key, value in condition.items():
                ands.append("json_extract(json, '$.%s') LIKE '%s'" % (key, value))
            if ands:
                ors.append("(" + " AND ".join(ands) + ")")

        cur = self.connection.cursor()
        query = "SELECT json FROM 'elements'"
        if ors:
            query += " WHERE %s" % " OR ".join(ors)

        rows = []
        LOGGER.debug("select query: %s", query)
        try:
            cur.execute(query)
            rows = cur.fetchall()
        except sqlite3.OperationalError as error:
            if "no such table" not in str(error):
                raise error
        finally:
            cur.close()

        for row in rows:
            yield self._row_to_element(row)

    def all(self) -> []:
        """
        Get all elements with any time from the ForensicStore
        :return: element generator with the results
        :rtype: [dict]
        """
        cur = self.connection.cursor()
        cur.execute("SELECT json FROM elements")
        for row in cur.fetchall():
            yield self._row_to_element(row)
        cur.close()

    ################################
    #   Intern
    ################################

    @staticmethod
    def _flatten_element(element: dict) -> ([], [], dict):
        # flatten element and discard empty lists
        flat_element = flatten_json.flatten(element, '.')
        column_names = []
        column_values = []
        for key, value in flat_element.items():
            if not isinstance(value, list) or (isinstance(value, list) and value):
                column_names.append(key)
                column_values.append(value)

        return column_names, column_values, flat_element

    @staticmethod
    def _row_to_element(row) -> dict:
        return json.loads(row['json'])

    @staticmethod
    def is_element_table(name: str):
        if name.startswith("sqlite") or name.startswith("_"):
            return False
        if name == "sqlar":
            return False
        if name == "elements":
            return False

        for suffix in ["_data", "_idx", "_content", "_docsize", "_config"]:
            if name.endswith(suffix):
                return False
        return True

    def _get_tables(self) -> dict:
        cur = self.connection.cursor()
        cur.execute("SELECT name FROM sqlite_master")

        tables = {}
        for table in cur.fetchall():
            if not self.is_element_table(table['name']):
                continue
            tables[table['name']] = set()
            cur.execute("PRAGMA table_info (\"{table}\")".format(
                table=table['name']))
            for col in cur.fetchall():
                tables[table['name']].add(col["name"])
        cur.close()

        return tables

    def _set_schema(self, name: str, schema: Any):
        if name in self._schemas and self._schemas[name] == schema:
            return
        self._schemas[name] = schema

    def _schema(self, name: str) -> Any:
        if name in self._schemas:
            return self._schemas[name]
        return None

    def getinfo(self, element_path, namespaces=None):
        """ Get info regarding a file or directory. """
        return self.fs.getinfo(element_path, namespaces)

    def listdir(self, element_path):
        """ Get a list of resources in a directory. """
        return self.fs.listdir(element_path)

    def makedir(self, element_path, permissions=None, recreate=False):
        """ Make a directory. """
        return self.fs.makedir(element_path, permissions, recreate)

    def openbin(self, element_path, mode=u'r', buffering=-1, **options):
        """ Open a binary file. """
        return self.fs.openbin(element_path, mode, buffering, **options)

    def remove(self, element_path):
        """ Remove a file. """
        return self.fs.remove(element_path)

    def removedir(self, element_path):
        """ Remove a directory. """
        return self.fs.removedir(element_path)

    def setinfo(self, element_path, info):
        """ Set resource information. """
        return self.fs.setinfo(element_path, info)

    def add_process_element(self, artifact, name, created, cwd, command_line, return_code, errors) -> str:
        """
        Add a new STIX 2.0 Process Object

        :param str artifact: Artifact name (non STIX field)
        :param str name: Specifies the name of the process.
        :param created: Specifies the date/time at which the process was created.
        :type created: datetime or str
        :param str cwd: Specifies the current working directory of the process.
        :param str command_line: Specifies the full command line used in executing the process, including the process
         name (depending on the operating system).
        :param int return_code: Return code of the process (non STIX field)
        :param list errors: List of errors
        :return: ID if the inserted element
        :rtype: str
        """
        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "process",
            "name": name,
            "created_time": created,
            "cwd": cwd,
            "command_line": command_line,
            "return_code": return_code,
            "errors": errors,
        })

    @contextmanager
    def add_process_element_stdout(self, element_id: str):
        """Creates a writeable context for the output on stdout of a process.

        :param str element_id: ID of the element
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        element = self.get(element_id)
        with self._add_file_field(element_id, element, "process", "stdout", "stdout_path") as the_file:
            yield the_file

    @contextmanager
    def add_process_element_stderr(self, element_id: str):
        """Creates a writeable context for the output on stderr of a process.

        :param str element_id: ID of the element
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        element = self.get(element_id)
        with self._add_file_field(element_id, element, "process", "stderr", "stderr_path") as the_file:
            yield the_file

    @contextmanager
    def add_process_element_wmi(self, element_id: str):
        """Creates a writeable context for the WMI output of a process.

        :param str element_id: ID of the element
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        element = self.get(element_id)
        with self._add_file_field(element_id, element, "process", "wmi", "wmi_path") as the_file:
            yield the_file

    def add_file_element(self, artifact, name, created, modified, accessed, origin, errors) -> str:
        """
        Add a new STIX 2.0 File Object

        :param str artifact: Artifact name (non STIX field)
        :param str name: Specifies the name of the file.
        :param created: Specifies the date/time the file was created.
        :type created: datetime or str
        :param modified: Specifies the date/time the file was last written to/modified.
        :type modified: datetime or str
        :param accessed: Specifies the date/time the file was last accessed.
        :type accessed: datetime or str
        :param dict origin: Origin of the file (non STIX field)
        :param list errors: List of errors
        :return: ID if the inserted element
        :rtype: str
        """
        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'
        if isinstance(accessed, datetime):
            accessed = accessed.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "file",
            "name": name,
            "ctime": created,
            "mtime": modified,
            "atime": accessed,
            "origin": origin,
            "errors": errors,
        })

    @contextmanager
    def add_file_element_export(self, element_id: str, export_name=None):
        """
        Creates a writeable context for the contents of the file. Size and hash values are automatically
        calculated for the written data.

        :param str element_id: ID of the element
        :param str export_name: Optional export name
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        element = self.get(element_id)
        if export_name is None:
            export_name = element["name"]
        with self._add_file_field(element_id, element, "file", export_name, "export_path", "size",
                                  "hashes") as the_file:
            yield the_file

    def add_registry_key_element(self, artifact, modified, key, errors) -> str:
        """
        Add a new STIX 2.0 Windows Registry Key Object

        :param str artifact: Artifact name (non STIX field)
        :param modified: Specifies the last date/time that the registry key was modified.
        :type modified: datetime or str
        :param str key: Specifies the full registry key including the hive.
        :param list errors: List of errors
        :return: ID if the inserted element
        :rtype: str
        """
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "windows-registry-key",
            "modified_time": modified,
            "key": key,
            "errors": errors,
        })

    def add_registry_value_element(self, key_id: str, data_type: str, data: bytes, name: str):
        """
        Add a STIX 2.0 Windows Registry Value Type

        :param str key_id: element ID of the parent windows registry key
        :param str data_type: Specifies the registry (REG_*) data type used in the registry value.
        :param bytes data: Specifies the data contained in the registry value.
        :param str name: Specifies the name of the registry value. For
            specifying the default value in a registry key, an empty string MUST be used.
        """
        values = self.get(key_id).get("values", [])
        if data_type in ("REG_SZ", "REG_EXPAND_SZ"):
            strdata = data.decode("utf-16")
        elif data_type in ("REG_DWORD", "REG_QWORD"):
            strdata = "%d" % int.from_bytes(data, "little")
        elif data_type == "MULTI_SZ":
            strdata = " ".join(data.decode("utf-16").split("\x00"))
        else:
            hexdata = data.hex()
            strdata = ' '.join(a + b for a, b in zip(hexdata[::2], hexdata[1::2]))

        values.append({"data_type": data_type, "data": strdata, "name": name})
        self.update(key_id, {"values": values})

    def add_directory_element(self, artifact: str, dir_path: str, created: Union[datetime, str],
                              modified: Union[datetime, str], accessed: Union[datetime, str], errors: [str]) -> str:
        """
        Add a new STIX 2.0 Directory Object

        :param str artifact: Artifact name (non STIX field)
        :param str dir_path: Specifies the path, as originally observed, to the directory on the file system.
        :param created: Specifies the date/time the file was created.
        :type created: datetime or str
        :param modified: Specifies the date/time the file was last written to/modified.
        :type modified: datetime or str
        :param accessed: Specifies the date/time the file was last accessed.
        :type accessed: datetime or str
        :param list errors: List of errors
        :return: ID if the inserted element
        :rtype: str
        """

        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'
        if isinstance(accessed, datetime):
            accessed = accessed.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "path": dir_path,
            "type": "directory",
            "ctime": created,
            "mtime": modified,
            "atime": accessed,
            "errors": errors,
        })

    @contextmanager
    def _add_file_field(self, element_id, element, element_type, export_name, field, size_field=None, hash_field=None):
        if element["type"] != element_type:
            raise TypeError("Must be a %s element" % element_type)

        file_path = fs.path.join(element.get("artifact", "."), export_name)

        with self.store_file(file_path) as (new_path, the_file):
            yield the_file

            update = {field: new_path}
            if hash_field is not None:
                update[hash_field] = the_file.get_hashes()

        if size_field is not None:
            update[size_field] = self.fs.getsize(new_path)

        self.update(element_id, update)


def new(url: str) -> ForensicStore:
    return ForensicStore(url, create=True)


def open(url: str) -> ForensicStore:  # pylint: disable=redefined-builtin
    return ForensicStore(url, create=False)

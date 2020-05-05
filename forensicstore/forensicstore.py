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
import logging
import os
import sqlite3
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

from .flatten_monkey import unflatten
from .hashed_file import HashedFile
from .resolver import ForensicStoreResolver
from .sqlitefs.sqlitefs import SQLiteFS

flatten_json.unflatten = unflatten

LOGGER = logging.getLogger(__name__)

DISCRIMINATOR = "type"


class StoreExitsError(Exception):
    pass


class StoreNotExitsError(Exception):
    pass


class ForensicStore:
    """
    ForensicStore is a class to database that can be used to store forensic elements and files.

    :param str url: Location of the database. Needs to be a path or a valid pyfilesystem2 url
    """

    def __init__(self, remote_url: str, create: bool):

        if isinstance(remote_url, str):
            exists = os.path.exists(remote_url)
            if exists and create:
                raise StoreExitsError
            elif not create and not exists:
                raise StoreNotExitsError
            if remote_url[-1] == "/":
                remote_url = remote_url[:-1]

        self.connection = sqlite3.connect(remote_url, timeout=1.0)
        self.connection.row_factory = sqlite3.Row
        self.fs = SQLiteFS(connection=self.connection)

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

        column_names, column_values, flat_element = self._flatten_element(element)

        self._ensure_table(column_names, flat_element, element)

        # insert element
        cur = self.connection.cursor()
        query = "INSERT INTO \"{table}\" ({columns}) VALUES ({values})".format(
            table=element[DISCRIMINATOR],
            columns=", ".join(['"' + c + '"' for c in column_names]),
            values=", ".join(['?'] * len(column_values))
        )
        LOGGER.debug("insert query: %s", query)
        try:
            cur.execute(query, column_values)
        except sqlite3.InterfaceError as error:
            print(query, column_values)
            raise error
        finally:
            cur.close()

        return element['id']

    def get(self, element_id: str) -> dict:
        """
        Get a single element by the element_id

        :param str element_id: ID of the element
        :return: Single element
        :rtype: dict
        """
        cur = self.connection.cursor()

        discriminator, _, _ = element_id.partition("--")

        try:
            cur.execute("SELECT * FROM \"{table}\" WHERE id=?".format(table=discriminator), (element_id,))
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
        old_discriminator = updated_element[DISCRIMINATOR]
        updated_element.update(partial_element)

        _, _, element_uuid = element_id.partition("--")

        # type changed
        if DISCRIMINATOR in partial_element and old_discriminator != partial_element[DISCRIMINATOR]:
            updated_element["id"] = partial_element[DISCRIMINATOR] + \
                                 '--' + element_uuid
            cur.execute("DELETE FROM \"{table}\" WHERE id=?".format(
                table=old_discriminator), [element_id])
            return self.insert(updated_element)

        column_names, _, flat_element = self._flatten_element(updated_element)

        self._ensure_table(column_names, flat_element, updated_element)

        values = []
        replacements = []
        for key, value in flat_element.items():
            replacements.append("\"%s\"=?" % key)
            values.append(value)
        replace = ", ".join(replacements)

        values.append(element_id)
        table = updated_element[DISCRIMINATOR]
        cur.execute("UPDATE \"{table}\" SET {replace} WHERE id=?".format(
            table=table, replace=replace), values)
        cur.close()

        return updated_element["id"]

    def import_jsonlite(self, url: str):
        """
        Import jsonlite file

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
        self.fs.close()
        # self.connection.commit()
        # self.connection.close()

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

    def jsonlite_handler(self, uri):
        return self._schema(uri)

    def validate_element_schema(self, element):
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

    def select(self, element_type: str, conditions=None) -> []:
        """
        Select elements from the ForensicStore

        :param str element_type: Type of the elements
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
                if key != "type":
                    ands.append("\"%s\" LIKE \"%s\"" % (key, value))
            if ands:
                ors.append("(" + " AND ".join(ands) + ")")

        cur = self.connection.cursor()
        query = "SELECT * FROM \"{table}\"".format(table=element_type)
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
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%sqlite%';")
        tables = cur.fetchall()

        for table_name in tables:
            table_name = table_name["name"]
            virtual_table_suffix = ("_data", "_idx", "_content", "_docsize", "_config")
            virtual_table = table_name.endswith(virtual_table_suffix)
            if not table_name.startswith("_") and not virtual_table and table_name != "sqlar":
                cur.execute("SELECT * FROM \"{table}\"".format(table=table_name))
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
        clean_result = dict()
        for k in row.keys():
            if row[k] is not None:
                clean_result[k] = row[k]

        return flatten_json.unflatten_list(clean_result, '.')

    def _get_tables(self) -> dict:
        cur = self.connection.cursor()
        cur.execute("SELECT name FROM sqlite_master")

        tables = {}
        for table in cur.fetchall():
            tables[table['name']] = {}
            cur.execute("PRAGMA table_info (\"{table}\")".format(
                table=table['name']))
            for col in cur.fetchall():
                tables[table['name']][col["name"]] = col["type"]
        cur.close()

        return tables

    def _ensure_table(self, column_names: [], flat_element: dict, element: dict):
        # create table if not exits
        if element[DISCRIMINATOR] not in self._tables:
            self._create_table(column_names, flat_element)
        # add missing columns
        else:
            missing_columns = set(flat_element.keys()) - \
                              set(self._tables[element[DISCRIMINATOR]])
            if missing_columns:
                self._add_missing_columns(
                    element[DISCRIMINATOR], flat_element, missing_columns)

    def _create_table(self, column_names: [], flat_element: dict):
        self._tables[flat_element[DISCRIMINATOR]] = {
            'id': 'TEXT', DISCRIMINATOR: 'TEXT'
        }
        columns = "id TEXT PRIMARY KEY, %s TEXT NOT NULL" % DISCRIMINATOR
        for column in column_names:
            if column not in [DISCRIMINATOR, 'id']:
                sql_data_type = self._get_sql_data_type(flat_element[column])
                self._tables[flat_element[DISCRIMINATOR]][column] = sql_data_type
                columns += ", \"{column}\" {sql_data_type}".format(
                    column=column, sql_data_type=sql_data_type
                )
        cur = self.connection.cursor()

        new_columns_str = ",".join(['"' + e + '"' for e in column_names])
        query = "CREATE VIRTUAL TABLE IF NOT EXISTS \"{}\" " \
                "USING fts5({}, tokenize=\"unicode61 tokenchars '{}'\");" \
            .format(flat_element[DISCRIMINATOR], new_columns_str, "/.")
        cur.execute(query)
        cur.close()
        self.connection.commit()
        self._tables = self._get_tables()

    def _add_missing_columns(self, table: str, columns: dict, new_columns: []):

        # Add column to virtual table (ALTER TABLE ... ADD COLUMN not allowed for virtual tables)
        # 1: Create new virtual table with additional column
        # 2: Fill new virtual table with data
        # 3: drop origin table
        # 4: rename new virtual table to origin table

        for new_column in new_columns:
            sql_data_type = self._get_sql_data_type(columns[new_column])
            self._tables[table][new_column] = sql_data_type

        tmp_table = "new_virtual_table"

        columns_new = self._tables[table].keys()
        columns_old = [e for e in columns_new if e not in new_columns]

        new_columns_str = ",".join(['"' + e + '"' for e in columns_new])
        old_columns_str = ",".join(['"' + e + '"' for e in columns_old])

        cur = self.connection.cursor()

        query = "CREATE VIRTUAL TABLE IF NOT EXISTS \"{}\" " \
                "USING fts5({}, tokenize=\"unicode61 tokenchars '{}'\");" \
            .format(tmp_table, new_columns_str, "/.")
        cur.execute(query)

        query = "INSERT INTO \"{}\"({}) SELECT * FROM \"{}\"".format(tmp_table, old_columns_str, table)
        cur.execute(query)

        query = "DROP TABLE \"{}\"".format(table)
        cur.execute(query)

        query = "ALTER TABLE \"{}\" RENAME TO \"{}\"".format(tmp_table, table)
        cur.execute(query)

        cur.close()

    @staticmethod
    def _get_sql_data_type(value: Any):
        if isinstance(value, int):
            return "INTEGER"
        return "TEXT"

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
        with self._add_file_field(element_id, element, "file", export_name, "export_path", "size", "hashes") as the_file:
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

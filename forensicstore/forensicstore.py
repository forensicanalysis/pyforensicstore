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
JSONLite is a database that can be used to store items and files.

"""

import hashlib
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from typing import Any, Union

import flatten_json
import jsonschema
import pkg_resources
from fs import path, open_fs, errors, base

from .flatten_monkey import unflatten
from .hashed_file import HashedFile
from .resolver import ForensicStoreResolver

flatten_json.unflatten = unflatten

LOGGER = logging.getLogger(__name__)

DISCRIMINATOR = "type"


def open_fs_file(location: str, create: bool = False) -> (base.FS, str):
    if isinstance(location, tuple):
        return location[0], location[1]

    filename = path.basename(location)
    try:
        file_system = open_fs(
            location[:-len(filename)], create=create)  # type: base.FS
    except errors.CreateFailed as error:
        raise RuntimeError("Could not create %s (%s)" % (location, error))
    return file_system, filename


class ForensicStore:
    """
    ForensicStore is a class to database that can be used to store forensic items and files.

    :param str url: Location of the database. Needs to be a path or a valid pyfilesystem2 url
    """

    db_file = "item.db"

    def __init__(self, remote_url: str, create: bool):
        if isinstance(remote_url, str):
            if remote_url[-1] == "/":
                remote_url = remote_url[:-1]
            self.remote_fs = open_fs(remote_url, create=True)
        else:
            self.remote_fs = remote_url

        self.new = not self.remote_fs.exists(self.db_file)

        dbpath = path.join(self.remote_fs.getsyspath("."), self.db_file)
        self.connection = sqlite3.connect(dbpath, timeout=10.0)
        self.connection.row_factory = sqlite3.Row

        self._schemas = dict()

        for entry_point in pkg_resources.iter_entry_points('forensicstore_schemas'):
            self._set_schema(entry_point.name, entry_point.load())

        self._tables = self._get_tables()

    ################################
    #   API
    ################################

    def insert(self, item: dict) -> str:
        """
        Insert a single item into the store

        :param dict item: New item
        :return: ID if the inserted item
        :rtype: int
        """
        if DISCRIMINATOR not in item:
            raise KeyError("Missing discriminator %s in item" % DISCRIMINATOR)
        # add uuid
        if 'uid' in item:
            item['id'] = item['uid']
            del item['uid']
        if 'id' not in item:
            item['id'] = item[DISCRIMINATOR] + '--' + str(uuid.uuid4())

        # discard empty values
        item = {k: v for k, v in item.items() if v is not None and not (isinstance(v, list) and not v)}

        validation_errors = self.validate_item_schema(item)
        if validation_errors:
            raise TypeError("item could not be validated", validation_errors)

        item['uid'] = item['id']
        del item['id']

        column_names, column_values, flat_item = self._flatten_item(item)

        self._ensure_table(column_names, flat_item, item)

        # insert item
        cur = self.connection.cursor()
        query = "INSERT INTO \"{table}\" ({columns}) VALUES ({values})".format(
            table=item[DISCRIMINATOR],
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

        return item['uid']

    def get(self, item_id: str) -> dict:
        """
        Get a single item by the item_id

        :param str item_id: ID of the item
        :return: Single item
        :rtype: dict
        """
        cur = self.connection.cursor()

        discriminator, _, _ = item_id.partition("--")

        try:
            cur.execute(
                "SELECT * FROM \"{table}\" WHERE uid=?".format(table=discriminator), (item_id,))
            result = cur.fetchone()
            if not result:
                raise KeyError("Item does not exist")

            return self._row_to_item(result)
        except sqlite3.OperationalError as error:
            raise KeyError(error)
        finally:
            cur.close()

    def query(self, query: str) -> []:
        cur = self.connection.cursor()
        cur.execute(query)
        for row in cur.fetchall():
            yield self._row_to_item(row)
        cur.close()

    def update(self, item_id: str, partial_item: dict) -> str:
        """
        Update a single item

        :param str item_id: ID of the item
        :param dict partial_item: Changes for the item
        """
        cur = self.connection.cursor()

        updated_item = self.get(item_id)
        old_discriminator = updated_item[DISCRIMINATOR]
        updated_item.update(partial_item)

        _, _, item_uuid = item_id.partition("--")

        # type changed
        if DISCRIMINATOR in partial_item and old_discriminator != partial_item[DISCRIMINATOR]:
            updated_item["uid"] = partial_item[DISCRIMINATOR] + \
                                  '--' + item_uuid
            cur.execute("DELETE FROM \"{table}\" WHERE uid=?".format(
                table=old_discriminator), [item_id])
            return self.insert(updated_item)

        column_names, _, flat_item = self._flatten_item(updated_item)

        self._ensure_table(column_names, flat_item, updated_item)

        values = []
        replacements = []
        for key, value in flat_item.items():
            replacements.append("\"%s\"=?" % key)
            values.append(value)
        replace = ", ".join(replacements)

        values.append(item_id)
        table = updated_item[DISCRIMINATOR]
        cur.execute("UPDATE \"{table}\" SET {replace} WHERE uid=?".format(
            table=table, replace=replace), values)
        cur.close()

        return updated_item["id"]

    def import_jsonlite(self, url: str):
        """
        Import jsonlite file

        :param str url: Location of the observed data file. Needs to be a path or a valid pyfilesystem2 url
        """
        import_db = open(url)
        for item in import_db.all():
            self._import_file(import_db.remote_fs, item)

    def _import_file(self, file_system, item: dict):
        for field in item:
            if field.endswith("_path"):
                with self.store_file(item[field]) as (file_path, file):
                    file.write(file_system.readbytes(item[field]))
                item.update({field: file_path})
        self.insert(item)

    @contextmanager
    def store_file(self, file_path: str) -> (str, HashedFile):
        """
        Creates a writeable context for the contents of the file.

        :param str file_path: Relative location of the new file
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        self.remote_fs.makedirs(path.dirname(file_path), recreate=True)
        i = 0
        base_path, ext = path.splitext(file_path)
        while self.remote_fs.exists(file_path):
            file_path = "%s_%d%s" % (base_path, i, ext)
            i += 1

        the_file = HashedFile(file_path, self.remote_fs)
        yield file_path, the_file
        the_file.close()

    @contextmanager
    def load_file(self, file_path: str):
        the_file = self.remote_fs.open(file_path)
        yield the_file
        the_file.close()

    def close(self):
        """
        Save ForensicStore to its location.
        """
        self.connection.commit()
        self.connection.close()

    ################################
    #   Validate
    ################################

    def validate(self):
        validation_errors = []
        expected_files = set()

        expected_files.add('/' + path.basename(self.db_file))

        for item in self.all():
            # validate item
            item_errors, item_expected_files = self.validate_item(item)
            validation_errors.extend(item_errors)
            expected_files |= item_expected_files

        stored_files = set({f for f in self.remote_fs.walk.files() if not f.endswith(
            '/' + path.basename(self.db_file) + "-journal")})

        if expected_files - stored_files:
            validation_errors.append("missing files: ('%s')" % "', '".join(expected_files - stored_files))
        if stored_files - expected_files:
            validation_errors.append("additional files: ('%s')" % "', '".join(stored_files - expected_files))

        return validation_errors

    def validate_item(self, item: dict):
        """
        Validate a single item

        :param dict item: Item for validation
        :raises TypeError: If item is invalid
        """
        validation_errors = []
        expected_files = set()

        if DISCRIMINATOR not in item:
            validation_errors.append("Item needs to have a discriminator, got %s" % item)

        validation_errors += self.validate_item_schema(item)

        # collect export paths
        for field in item.keys():
            if field.endswith("_path"):
                export_path = item[field]

                # validate parent paths
                if '..' in export_path:
                    validation_errors.append("'..' in %s" % export_path)
                    continue

                expected_files.add('/' + export_path)

                # validate existence, is validated later as well
                if not self.remote_fs.exists(item[field]):
                    continue

                # validate size
                if "size" in item:
                    if item["size"] != self.remote_fs.getsize(export_path):
                        validation_errors.append("wrong size for %s" % export_path)

                if "hashes" in item:
                    for hash_algorithm_name, value in item["hashes"].items():
                        if hash_algorithm_name == "MD5":
                            hash_algorithm = hashlib.md5()
                        elif hash_algorithm_name == "SHA-1":
                            hash_algorithm = hashlib.sha1()
                        else:
                            validation_errors.append("unsupported hash %s for %s" % (hash_algorithm_name, export_path))
                            continue
                        hash_algorithm.update(self.remote_fs.readbytes(export_path))
                        if hash_algorithm.hexdigest() != value:
                            validation_errors.append(
                                "hashvalue mismatch %s for %s" % (hash_algorithm_name, export_path)
                            )

        return validation_errors, expected_files

    def jsonlite_handler(self, uri):
        return self._schema(uri)

    def validate_item_schema(self, item):
        validation_errors = []

        item_type = item[DISCRIMINATOR]
        schema = self._schema(item_type)
        if schema is None:
            return validation_errors

        try:
            jsonschema.validate(item, schema, resolver=ForensicStoreResolver(self, item_type))
        except jsonschema.ValidationError as error:
            validation_errors.append("Item could not be validated, %s" % str(error))
        return validation_errors

    def select(self, item_type: str, conditions=None) -> []:
        """
        Select items from the ForensicStore

        :param str item_type: Type of the items
        :param [dict] conditions: List of key values pairs. Items matching any list element are returned
        :return: Item generator with the results
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
        query = "SELECT * FROM \"{table}\"".format(table=item_type)
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
            yield self._row_to_item(row)

    def all(self) -> []:
        """
        Get all items with any time from the ForensicStore
        :return: Item generator with the results
        :rtype: [dict]
        """
        cur = self.connection.cursor()
        cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE '%sqlite%';")
        tables = cur.fetchall()

        for table_name in tables:
            table_name = table_name["name"]
            virtual_table_suffix = ("_data", "_idx", "_content", "_docsize", "_config")
            if not table_name.startswith("_") and not table_name.endswith(virtual_table_suffix):
                cur.execute(
                    "SELECT * FROM \"{table}\"".format(table=table_name))
                for row in cur.fetchall():
                    yield self._row_to_item(row)
        cur.close()

    ################################
    #   Intern
    ################################

    @staticmethod
    def _flatten_item(item: dict) -> ([], [], dict):
        # flatten item and discard empty lists
        flat_item = flatten_json.flatten(item, '.')
        column_names = []
        column_values = []
        for key, value in flat_item.items():
            if not isinstance(value, list) or (isinstance(value, list) and value):
                column_names.append(key)
                column_values.append(value)

        return column_names, column_values, flat_item

    @staticmethod
    def _row_to_item(row) -> dict:
        clean_result = dict()
        for k in row.keys():
            if row[k] is not None:
                clean_result[k] = row[k]

        clean_result['id'] = clean_result['uid']
        del clean_result['uid']

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

    def _ensure_table(self, column_names: [], flat_item: dict, item: dict):
        # create table if not exits
        if item[DISCRIMINATOR] not in self._tables:
            self._create_table(column_names, flat_item)
        # add missing columns
        else:
            missing_columns = set(flat_item.keys()) - \
                              set(self._tables[item[DISCRIMINATOR]])
            if missing_columns:
                self._add_missing_columns(
                    item[DISCRIMINATOR], flat_item, missing_columns)

    def _create_table(self, column_names: [], flat_item: dict):
        self._tables[flat_item[DISCRIMINATOR]] = {
            'uid': 'TEXT', DISCRIMINATOR: 'TEXT'
        }
        columns = "uid TEXT PRIMARY KEY, %s TEXT NOT NULL" % DISCRIMINATOR
        for column in column_names:
            if column not in [DISCRIMINATOR, 'uid']:
                sql_data_type = self._get_sql_data_type(flat_item[column])
                self._tables[flat_item[DISCRIMINATOR]][column] = sql_data_type
                columns += ", \"{column}\" {sql_data_type}".format(
                    column=column, sql_data_type=sql_data_type
                )
        cur = self.connection.cursor()

        new_columns_str = ",".join(['"' + e + '"' for e in column_names])
        query = "CREATE VIRTUAL TABLE IF NOT EXISTS \"{}\" " \
                "USING fts5({}, tokenize=\"unicode61 tokenchars '{}'\");" \
            .format(flat_item[DISCRIMINATOR], new_columns_str, "/.")
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

    def getinfo(self, item_path, namespaces=None):
        """ Get info regarding a file or directory. """
        return self.remote_fs.getinfo(item_path, namespaces)

    def listdir(self, item_path):
        """ Get a list of resources in a directory. """
        return self.remote_fs.listdir(item_path)

    def makedir(self, item_path, permissions=None, recreate=False):
        """ Make a directory. """
        return self.remote_fs.makedir(item_path, permissions, recreate)

    def openbin(self, item_path, mode=u'r', buffering=-1, **options):
        """ Open a binary file. """
        return self.remote_fs.openbin(item_path, mode, buffering, **options)

    def remove(self, item_path):
        """ Remove a file. """
        return self.remote_fs.remove(item_path)

    def removedir(self, item_path):
        """ Remove a directory. """
        return self.remote_fs.removedir(item_path)

    def setinfo(self, item_path, info):
        """ Set resource information. """
        return self.remote_fs.setinfo(item_path, info)

    def add_process_item(self, artifact, name, created, cwd, arguments, command_line, return_code, errors) -> str:
        """
        Add a new STIX 2.0 Process Object

        :param str artifact: Artifact name (non STIX field)
        :param str name: Specifies the name of the process.
        :param created: Specifies the date/time at which the process was created.
        :type created: datetime or str
        :param str cwd: Specifies the current working directory of the process.
        :param [str] arguments: Specifies the list of arguments used in executing the process. Each argument MUST be
         captured separately as a string.
        :param str command_line: Specifies the full command line used in executing the process, including the process
         name (depending on the operating system).
        :param int return_code: Return code of the process (non STIX field)
        :param list errors: List of errors
        :return: ID if the inserted item
        :rtype: str
        """
        if isinstance(created, datetime):
            created = created.isoformat(timespec='milliseconds') + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "process",
            "name": name,
            "created": created,
            "cwd": cwd,
            "arguments": arguments,
            "command_line": command_line,
            "return_code": return_code,
            "errors": errors,
        })

    @contextmanager
    def add_process_item_stdout(self, item_id: str):
        """Creates a writeable context for the output on stdout of a process.

        :param str item_id: ID of the item
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        with self._add_file_field(item_id, item, "process", "stdout", "stdout_path") as the_file:
            yield the_file

    @contextmanager
    def add_process_item_stderr(self, item_id: str):
        """Creates a writeable context for the output on stderr of a process.

        :param str item_id: ID of the item
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        with self._add_file_field(item_id, item, "process", "stderr", "stderr_path") as the_file:
            yield the_file

    @contextmanager
    def add_process_item_wmi(self, item_id: str):
        """Creates a writeable context for the WMI output of a process.

        :param str item_id: ID of the item
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        with self._add_file_field(item_id, item, "process", "wmi", "wmi_path") as the_file:
            yield the_file

    def add_file_item(self, artifact, name, created, modified, accessed, origin, errors) -> str:
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
        :return: ID if the inserted item
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
            "created": created,
            "modified": modified,
            "accessed": accessed,
            "origin": origin,
            "errors": errors,
        })

    @contextmanager
    def add_file_item_export(self, item_id: str, export_name=None):
        """
        Creates a writeable context for the contents of the file. Size and hash values are automatically
        calculated for the written data.

        :param str item_id: ID of the item
        :param str export_name: Optional export name
        :return: A file object with a .write method
        :rtype: HashedFile
        """
        item = self.get(item_id)
        if export_name is None:
            export_name = item["name"]
        with self._add_file_field(item_id, item, "file", export_name, "export_path", "size", "hashes") as the_file:
            yield the_file

    def add_registry_key_item(self, artifact, modified, key, errors) -> str:
        """
        Add a new STIX 2.0 Windows Registry Key Object

        :param str artifact: Artifact name (non STIX field)
        :param modified: Specifies the last date/time that the registry key was modified.
        :type modified: datetime or str
        :param str key: Specifies the full registry key including the hive.
        :param list errors: List of errors
        :return: ID if the inserted item
        :rtype: str
        """
        if isinstance(modified, datetime):
            modified = modified.isoformat()[0:-3] + 'Z'

        return self.insert({
            "artifact": artifact,
            "type": "windows-registry-key",
            "modified": modified,
            "key": key,
            "errors": errors,
        })

    def add_registry_value_item(self, key_id: str, data_type: str, data: bytes, name: str):
        """
        Add a STIX 2.0 Windows Registry Value Type

        :param str key_id: Item ID of the parent windows registry key
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

    def add_directory_item(self, artifact: str, dir_path: str, created: Union[datetime, str],
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
        :return: ID if the inserted item
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
            "created": created,
            "modified": modified,
            "accessed": accessed,
            "errors": errors,
        })

    @contextmanager
    def _add_file_field(self, item_id, item, item_type, export_name, field, size_field=None, hash_field=None):
        if item["type"] != item_type:
            raise TypeError("Must be a %s item" % item_type)

        file_path = path.join(item.get("artifact", "."), export_name)

        with self.store_file(file_path) as (new_path, the_file):
            yield the_file

            update = {field: new_path}
            if hash_field is not None:
                update[hash_field] = the_file.get_hashes()

        if size_field is not None:
            update[size_field] = self.remote_fs.getsize(new_path)

        self.update(item_id, update)


def new(url: str) -> ForensicStore:
    return ForensicStore(url, create=True)


def open(url: str) -> ForensicStore:
    return ForensicStore(url, create=False)

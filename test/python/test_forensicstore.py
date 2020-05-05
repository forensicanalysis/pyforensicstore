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

import datetime
import os
import shutil
import tempfile
from unittest import SkipTest

import pytest

import forensicstore
from .example_forensicstore import EXAMPLE_FORENSICSTORE


@pytest.fixture
def out_dir(tmpdir_factory):
    return tempfile.mkdtemp()


@pytest.fixture
def data(tmpdir_factory):
    tmpdir = tempfile.mkdtemp()
    os.makedirs(tmpdir + "/data")
    shutil.copytree("test/forensicstore", tmpdir + "/data/forensicstore/")
    shutil.copytree("test/json", tmpdir + "/data/json/")
    return tmpdir + "/data"


class TestForensicStore:

    def test_init_create(self, out_dir, data):
        store = forensicstore.new(out_dir + "/init_create.forensicstore")
        store.close()
        assert os.path.exists(out_dir + "/init_create.forensicstore")
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_process_element(self, out_dir, data):
        store = forensicstore.new(out_dir + "/iptables.forensicstore")
        cmd_date = datetime.datetime(2016, 1, 20, 14, 11, 25, 550000)
        cmd = store.add_process_element("IPTablesRules", "iptables", cmd_date, "/root/", "/sbin/iptables -L -n -v", 0,
                                        [])
        with store.add_process_element_stdout(cmd) as stdout, store.add_process_element_stderr(cmd) as stderr:
            stdout.write(b"foo")
            stderr.write(b"bar")

        elements = store.all()
        first = list(elements).pop()
        del first["id"]
        assert first == EXAMPLE_FORENSICSTORE[0]

        with store.fs.open("/IPTablesRules/stdout", 'rb') as io:
            assert io.read() == b"foo"
        with store.fs.open("/IPTablesRules/stderr", 'rb') as io:
            assert io.read() == b"bar"
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_file_element(self, out_dir, data):
        store = forensicstore.new(out_dir + "/amcache.forensicstore")
        file_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        origin = {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        }
        file = store.add_file_element("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin,
                                      [])
        with store.add_file_element_export(file) as export:
            export.write(123 * b'A')

        elements = store.all()
        first = list(elements).pop()
        del first["id"]
        assert first == EXAMPLE_FORENSICSTORE[2]

        with store.fs.open("/WindowsAMCacheHveFile/Amcache.hve", 'rb') as io:
            assert io.read() == 123 * b'A'
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_duplicate_file_element(self, out_dir, data):
        store = forensicstore.new(out_dir + "/amcache.forensicstore")
        file_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        origin = {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        }
        file1 = store.add_file_element("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin,
                                       [])
        with store.add_file_element_export(file1) as export:
            export.write(123 * b'A')

        file2 = store.add_file_element("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin,
                                       [])
        with store.add_file_element_export(file2) as export:
            export.write(123 * b'B')

        file3 = store.add_file_element("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin,
                                       [])
        with store.add_file_element_export(file3, "Amcache_b.hve") as export:
            export.write(123 * b'C')

        file4 = store.add_file_element("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin,
                                       [])
        with store.add_file_element_export(file4, "Amcache_b.hve") as export:
            export.write(123 * b'D')

        first = store.get(file1)
        del first["id"]
        assert first == EXAMPLE_FORENSICSTORE[2]

        with store.fs.open("/WindowsAMCacheHveFile/Amcache.hve", 'rb') as io:
            assert io.read() == 123 * b'A'
        with store.fs.open("/WindowsAMCacheHveFile/Amcache_0.hve", 'rb') as io:
            assert io.read() == 123 * b'B'
        with store.fs.open("/WindowsAMCacheHveFile/Amcache_b.hve", 'rb') as io:
            assert io.read() == 123 * b'C'
        with store.fs.open("/WindowsAMCacheHveFile/Amcache_b_0.hve", 'rb') as io:
            assert io.read() == 123 * b'D'
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_multi_write_file_element(self, out_dir, data):
        store = forensicstore.new(out_dir + "/amcache.forensicstore")
        file_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        origin = {
            "path": "C:\\Windows\\appcompat\\Programs\\Amcache.hve",
            "volume": "2"
        }
        file = store.add_file_element("WindowsAMCacheHveFile", "Amcache.hve", file_date, file_date, file_date, origin,
                                      [])
        with store.add_file_element_export(file) as export:
            for _ in range(123):
                export.write(b'A')

        elements = store.all()
        first = list(elements).pop()

        del first["id"]
        assert first == EXAMPLE_FORENSICSTORE[2]

        with store.fs.open("/WindowsAMCacheHveFile/Amcache.hve", 'rb') as io:
            assert io.read() == 123 * b'A'

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_directory_element(self, out_dir, data):
        store = forensicstore.new(out_dir + "/program_files.forensicstore")
        dir_date = datetime.datetime(2014, 9, 11, 21, 50, 18, 301000)
        store.add_directory_element("WindowsEnvironmentVariableProgramFiles", "C:\\Program Files", dir_date, dir_date,
                                    dir_date, [])
        elements = store.all()
        first = list(elements).pop()
        del first["id"]
        assert first == EXAMPLE_FORENSICSTORE[3]

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_registry_key_element(self, out_dir, data):
        store = forensicstore.new(out_dir + "/codepage.forensicstore")
        key_date = datetime.datetime(2009, 7, 14, 4, 34, 14, 225000)
        key = store.add_registry_key_element("WindowsCodePage", key_date,
                                             "HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Nls\\CodePage",
                                             [])
        store.add_registry_value_element(key, "REG_SZ", "1252".encode("utf-16"), "ACP")

        elements = store.all()
        first = list(elements).pop()
        del first["id"]
        assert first == EXAMPLE_FORENSICSTORE[5]

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    # @pytest.mark.benchmark(group="get")
    # def test_bench_get(self, benchmark, out_dir, data):
    #     store = forensicstore.new(data + "/valid/example1.forensicstore")
    #     for i in range(100):
    #         store.import_observed_data_file(data + "/json/example1.json")
    #     benchmark(store.get, "process", 0)
    #     shutil.rmtree(out_dir)
    #     shutil.rmtree(data)

    # @pytest.mark.benchmark(group="add")
    # def test_bench_add(self, benchmark, out_dir, data):
    #     store = forensicstore.new(out_dir + "/benchmark1.forensicstore")
    #     for i in range(100):
    #         store.import_observed_data_file(data + "/json/example1.json")
    #     benchmark(store.add, {"type": "file", "name": "bar"})
    #     shutil.rmtree(out_dir)
    #     shutil.rmtree(data)

    def test_init_create(self, out_dir, data):
        store = forensicstore.new(out_dir + "/init_create.forensicstore")
        store.close()

        assert os.path.exists(out_dir + "/init_create.forensicstore")

        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_init_create_ref(self, out_dir, data):
        cwd = os.getcwd()
        os.chdir(out_dir)
        store = forensicstore.new("init_create.forensicstore")
        store.close()
        os.chdir(cwd)

        assert os.path.exists(out_dir + "/init_create.forensicstore")

        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_init_load(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_save(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_get(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        first = store.get("process--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "id": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "process",
            "name": "iptables",
            "created_time": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0
        }
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_get_not_existing(self, out_dir, data):
        with pytest.raises(forensicstore.forensicstore.StoreNotExitsError):
            store = forensicstore.open(data + "/non_existing.forensicstore")
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_select(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.select("file"))) == 2
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_all(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.all())) == 7
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_insert(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.all())) == 7
        store.insert(
            {"type": "foo", "id": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"})
        assert len(list(store.all())) == 8
        assert store.get("foo--2cd66ab1-9b85-4110-8d77-4b6906819693") == {
            "type": "foo", "id": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"}
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_insert_empty_list(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        assert len(list(store.all())) == 7
        store.insert({"type": "foo", "list": [],
                      "id": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"})
        assert len(list(store.all())) == 8
        assert store.get("foo--2cd66ab1-9b85-4110-8d77-4b6906819693") == {
            "type": "foo", "id": "foo--2cd66ab1-9b85-4110-8d77-4b6906819693"}
        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_column(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        store.update(
            "process--920d7c41-0fef-4cf8-bce2-ead120f6b506", {"new_column": "foo"})
        assert len(list(store.all())) == 7

        first = store.get("process--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "id": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "process",
            "name": "iptables",
            "created_time": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0,
            "new_column": "foo"
        }

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_add_type_add_column(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")

        element_id = store.insert({"type": "foo"})
        store.update(element_id, {"new_column": '"foo"'})

        first = store.get(element_id)
        assert first == {
            "id": element_id,
            "new_column": '"foo"',
            "type": "foo",
        }

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_update(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        store.update(
            "process--920d7c41-0fef-4cf8-bce2-ead120f6b506", {"name": "foo"})
        assert len(list(store.all())) == 7

        first = store.get("process--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "id": "process--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "process",
            "name": "foo",
            "created_time": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0
        }

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_update_type(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        store.update("process--920d7c41-0fef-4cf8-bce2-ead120f6b506", {"type": "foo"})
        assert len(list(store.all())) == 7

        first = store.get("foo--920d7c41-0fef-4cf8-bce2-ead120f6b506")
        assert first == {
            "id": "foo--920d7c41-0fef-4cf8-bce2-ead120f6b506",
            "artifact": "IPTablesRules",
            "type": "foo",
            "name": "iptables",
            "created_time": "2016-01-20T14:11:25.550Z",
            "cwd": "/root/",
            "command_line": "/sbin/iptables -L -n -v",
            "stdout_path": "IPTablesRules/stdout",
            "stderr_path": "IPTablesRules/stderr",
            "return_code": 0
        }

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_import_store(self, out_dir, data):
        import_store = forensicstore.new(out_dir + "/tmp.forensicstore")
        with import_store.store_file("testfile.txt") as (path, io):
            io.write(123 * b'A')
            import_store.insert({"type": "foo", "export_path": path})
        import_store.close()

        store = forensicstore.new(out_dir + "/amcache.forensicstore")
        with store.store_file("testfile.txt") as (path, io):
            io.write(123 * b'B')
            store.insert({"type": "foo", "export_path": path})

        store.import_forensicstore(out_dir + "/tmp.forensicstore")

        elements = store.all()
        assert len(list(elements)) == 2
        with store.fs.open("/testfile.txt", 'rb') as io:
            assert io.read() == 123 * b'B'
        with store.fs.open("/testfile_0.txt", 'rb') as io:
            assert io.read() == 123 * b'A'

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_insert_quotes(self, out_dir, data):
        store = forensicstore.new(out_dir + "/quotes.forensicstore")

        element_id = store.insert({"type": "any_type"})
        store.update(element_id, {"foo": '@"%ProgramFiles%\\Windows Journal\\Journal.exe",-3072'})

        assert store.get(element_id)["foo"] == '@"%ProgramFiles%\\Windows Journal\\Journal.exe",-3072'

        store.close()
        shutil.rmtree(out_dir)
        shutil.rmtree(data)

    def test_query_fts(self, out_dir, data):
        store = forensicstore.open(data + "/forensicstore/example1.forensicstore")
        res = list(store.query('SELECT * FROM process WHERE process MATCH (\'"IPTablesRules" OR "powershell"\')'))
        assert len(res) == 2
        print(res[0].keys())
        assert res[0]['id'] == "process--920d7c41-0fef-4cf8-bce2-ead120f6b506"
        assert res[1]['id'] == "process--9da4aa39-53b8-412e-b3cd-6b26c772ad4d"

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

import argparse
import json
import sys

import forensicstore


def main():
    root_parser = argparse.ArgumentParser(description='Handle forensicstores')
    root_subparsers = root_parser.add_subparsers(dest='root_command')
    root_subparsers.required = True

    create_parser = root_subparsers.add_parser("create")
    create_parser.add_argument('store')

    import_parser = root_subparsers.add_parser("import")
    import_parser.add_argument('url')
    import_parser.add_argument('store')

    validate_parser = root_subparsers.add_parser("validate")
    validate_parser.add_argument('store')
    validate_parser.add_argument('--no-fail', action='store_true', dest="nofail")

    element_parser = root_subparsers.add_parser("element")
    element_subparsers = element_parser.add_subparsers(dest='command')
    element_subparsers.required = True

    get_parser = element_subparsers.add_parser("get")
    get_parser.add_argument('id')
    get_parser.add_argument('store')

    select_parser = element_subparsers.add_parser("select")
    select_parser.add_argument('type')
    select_parser.add_argument('store')

    all_parser = element_subparsers.add_parser("all")
    all_parser.add_argument('store')

    insert_parser = element_subparsers.add_parser("insert")
    insert_parser.add_argument('json')
    insert_parser.add_argument('store')

    update_parser = element_subparsers.add_parser("update")
    update_parser.add_argument('id')
    update_parser.add_argument('json')
    update_parser.add_argument('store')

    args = root_parser.parse_args()

    if args.root_command == "create":
        store = forensicstore.new(args.store)
        store.close()
    elif args.root_command == "validate":
        store = forensicstore.open(args.store)
        errors = store.validate()
        if errors:
            print(json.dumps(errors))
        if args.nofail:
            sys.exit(0)
        sys.exit(len(errors))
    elif args.root_command == "element":
        if args.command == "get":
            store = forensicstore.open(args.store)
            element = store.get(args.id)
            print(json.dumps(element))
            store.close()
        elif args.command == "select":
            store = forensicstore.open(args.store)
            elements = list(store.select([{"type": args.type}]))
            print(json.dumps(elements))
            store.close()
        elif args.command == "all":
            store = forensicstore.open(args.store)
            elements = list(store.all())
            print(json.dumps(elements))
            store.close()
        elif args.command == "insert":
            store = forensicstore.open(args.store)
            element = store.insert(json.loads(args.json))
            print(json.dumps(element))
            store.close()
        elif args.command == "update":
            store = forensicstore.open(args.store)
            print(args.json)
            element = store.update(args.id, json.loads(args.json))
            print(json.dumps(element))
            store.close()
        else:
            NotImplementedError("Sub command %s does not exist" % args.command)
    else:
        NotImplementedError("Command %s does not exist" % args.root_command)


if __name__ == '__main__':
    main()

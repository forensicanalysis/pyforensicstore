<h1 align="center">pyforensicstore</h1>

<p  align="center">
 <a href="https://github.com/forensicanalysis/pyforensicstore/actions"><img src="https://github.com/forensicanalysis/pyforensicstore/workflows/CI/badge.svg" alt="build" /></a>
 <a href="https://codecov.io/gh/forensicanalysis/pyforensicstore"><img src="https://codecov.io/gh/forensicanalysis/pyforensicstore/branch/master/graph/badge.svg" alt="coverage" /></a>
<a href='https://forensicstore.readthedocs.io/en/latest/?badge=latest'><img src='https://readthedocs.org/projects/forensicstore/badge/?version=latest' alt='Documentation Status' /></a>
</p>


![](docs/forensicstore.png)


The forensicstore project contains Python libraries to create,
access and process forensic artifacts bundled in so called forensicstores
(a database for metadata and subfolders with forensic artifacts).

## The forensicstore format
The forensicstore format implements the following conventions:

- The forensicstore is a folder containing an item.db file and an arbitrary number of other folders.
- The item.db file contains metadata for all extracted artifacts in a forensic investigation in jsonlite format (flattened json objects in a sqlite database).
- Items are represented as json objects.
- Items are valid STIX 2.0 Observable Objects where applicable.
- Items must not have dots (".") in their json keys.
- Files stored in the forensicstore are referenced by item attributes ending in _path, e.g. export_path, stdout_path and wmi_path.
- Any item stored in the forensicstore can have an errors attribute that contains errors that are related to retrival or pro-cessing of this item.
## Structure
An example directory structure for a forensicstore:

```
example.forensicstore/
├── ChromeCache
│   ├── 0003357376fd75df_0
│   └── ...
├── ChromeHistory
│   └── History
├── ...
└── item.db
```

### Installation

Python installation can be easily done via pip:

```bash
pip install forensicstore
```

### Usage

```python
import forensicstore

if __name__ == '__main__':
    store = forensicstore.connect("example1.forensicstore")
    store.insert({"type": "file", "name": "test.txt"})
    store.close()
```

## Contact

For feedback, questions and discussions you can use the [Open Source DFIR Slack](https://github.com/open-source-dfir/slack).

## Acknowledgment

The development of this software was partially sponsored by Siemens CERT, but
is not an official Siemens product.

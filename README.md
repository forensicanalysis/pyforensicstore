<h1 align="center">pyforensicstore</h1>

<p  align="center">
 <a href="https://github.com/forensicanalysis/pyforensicstore/actions"><img src="https://github.com/forensicanalysis/pyforensicstore/workflows/CI/badge.svg" alt="build" /></a>
 <a href="https://codecov.io/gh/forensicanalysis/pyforensicstore"><img src="https://codecov.io/gh/forensicanalysis/pyforensicstore/branch/master/graph/badge.svg" alt="coverage" /></a>
 <a href="https://pypi.org/project/forensicstore/"><img alt="PyPI" src="https://img.shields.io/pypi/v/forensicstore?color=blue"></a>
<a href='https://forensicstore.readthedocs.io/en/latest/?badge=latest'><img src='https://readthedocs.org/projects/forensicstore/badge/?version=latest' alt='Documentation Status' /></a>
</p>

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

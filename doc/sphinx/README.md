# Sphinx documentation

Sphinx documentation that can be used to generate python docs.

To generate:

```
pip3 install sphinx
make clean
make html
python3 -m http.server 8009 --directory build/html
```

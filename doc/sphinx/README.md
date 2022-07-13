# Sphinx documentation

Sphinx documentation that can be used to generate python docs.

To generate:

```
# Clone fuzz-introspector
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector

# Create virtual environment and install dependencies
python3 -m venv .venv
. .venv/bin/activate
pip3 install -r requirements.txt

cd doc/sphinx
make clean
make html
python3 -m http.server 8009 --directory build/html
```

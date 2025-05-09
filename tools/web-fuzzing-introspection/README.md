# Fuzz Introspector macro website UI


This app is used to display fuzz introspector data for many projects in a single
unified manner. The main usage of this is https://introspector.oss-fuzz.com/

In order to launch this website first step is to create a DB and then it's
ready to launch. The DB creator script scans Fuzz Introspector reports as
generated by OSS-Fuzz. The webapp will then display this data and make it
available through various APIs.

## Launching a local version

This webapp currently is build, tested and run with Python 3.11. Other versions
may work but are not officially supported.

To launch the web app locally you need to:

1. Create a virtual environment and install dependencies.
2. Create a local DB. This requires one command and takes a few minutes to
   create a small DB with 10-20 OSS-Fuzz projects.
3. Launch the web app.

The following commands can be used to launch a version of the webapp using
a subset of the projects on OSS-Fuzz.

```bash
# Get source
git clone https://github.com/ossf/fuzz-introspector
cd tools/web-fuzzing-introspection

# Create virtual environment
python3.11 -m virtualenv .venv
. .venv/bin/activate
python3.11 -m pip install -r ./requirements.txt


# Create (small) DB
cd app/static/assets/db/
launch_minor_oss_fuzz.sh
cd ../../../

# Start the web app
python3 ./main.py
# ...
# Should show output along the lines of:
# Not setting google tag
# Loading db
# ...
#  * Serving Flask app 'main'
#  * Debug mode: off
# WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
#  * Running on all addresses (0.0.0.0)
#  * Running on http://127.0.0.1:8080
#  * Running on http://10.0.2.15:8080
# Press CTRL+C to quit
```

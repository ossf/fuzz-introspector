# Install
python3 -m virtualenv .venv
. .venv/bin/activate
pip3 install -r ./requirements.txt

# Run website
FLASK_APP=app python3 -m flask run

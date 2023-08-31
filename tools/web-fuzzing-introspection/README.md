# Install

```bash
python3 -m virtualenv .venv
. .venv/bin/activate
pip3 install -r ./requirements.txt

cd app/static/assets/db/
python3 python3 ./web_db_creator_from_summary.py --max-projects=50
cd ../../../
python3 ./main.py
```

`web_db_creator_from_summary.py` creates all of the data that the website digests.
It has several options available to configure, e.g. how many projects to analyse
and how far back the analysis should be done.

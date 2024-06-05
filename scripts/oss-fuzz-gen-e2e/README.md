# OSS-Fuzz-gen helper scripts

This foler contains various helper scripts to run [OSS-Fuzz-gen](https://github.com/google/oss-fuzz-gen).
OSS-Fuzz-gen relies on Fuzz Introspector to provide data about the target under
analysis, and relies on the web API to make the data available. The benefit
of this is that the web API makes it possible to easily query data about
many OSS-Fuzz projects ([https://introspector.oss-fuzz.com/api](https://introspector.oss-fuzz.com/api)).
However, there are several locations where logic in Fuzz Introspector can be
changed in order to impact OSS-Fuzz-gen:
1) The frontends
2) The post-processing
3) The web api

Each of these steps are part of the OSS-Fuzz-gen pipeline.

The main purpose of the logic in this folder is to enable the full OSS-Fuzz-gen
pipeline based on a local set up.


## Usage

Example running of this pipeline:

```sh
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/scripts/oss-fuzz-gen-e2e

# Set up OSS-Fuzz-gen and build a version of OSS-Fuzz images based on the
# current local Fuzz Introspector.
./build_all.sh

# Run an OSS-Fuzz-gen pipeline that relies on a local run of FI and a local
# version of the webapp. This includes generating a new set of benchmarks for
# the selected projects.
export MODEL=gpt-3.5-turbo
export OPENAI_API_KEY=...
./run_all.sh cjson htslib

# Show the web report created by OSS-Fuzz-gen
cd workdir
. .venv/bin/activate
cd oss-fuzz-gen
python3 -m report.web ./results/ 8012
```

The above steps can be rerun once changes in the FI has been applied. As such,
these steps are the recommended steps to use during testing and development.

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

### Running with a local Webapp

We can run OSS-Fuzz-gen using a local version of the webapp. This is useful
for testing changes in the webapp, such as exposing new API endpoints, or to
ensure a reliably network connection. This is the preferred way of running
OSS-Fuzz-gen for some of the Fuzz Introspector maintainers.

The `web_run_all.sh` is the script responsible for this.

To do this, we can use the following steps:

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
./web_run_all.sh cjson htslib

# Show the web report created by OSS-Fuzz-gen
cd workdir
. .venv/bin/activate
cd oss-fuzz-gen
python3 -m report.web -r ./results/ -s
```

It's only needed to run `build_all.sh` once, so after having done the above
once then it's possible to run `web_run_all.sh` any number of times without
having to do the `build_all.sh` again.

### Running with a locally adjusted Fuzz Introspector core

It's possible to run OSS-Fuzz-gen in a way where we apply changes from the
core of Fuzz Introspector. This means that, if we have made changes in the
Fuzz Introspector frontends, such as the LLVM logic, or in the `src/` folder,
then we can test these changes and how they apply in OSS-Fuzz-gen.

The tricky bit here is that we need to build and run the fuzzers first,
then apply the post processing, and then have the webapp prepare it for use by
OSS-Fuzz-gen. Furthermore, we need to do this after having build the new
Docker images that rely on our changes.

The `run_all.sh` is the key script for doing this.

We can do this using the following steps:

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
python3 -m report.web -r ./results/ -s
```

The above steps can be rerun once changes in the FI has been applied. As such,
these steps are the recommended steps to use during testing and development.

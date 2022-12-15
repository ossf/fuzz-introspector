# OSS-Fuzz integration

The easiest way to test the introspector is to do it by way of OSS-Fuzz.
OSS-Fuzz supports fuzz introspector and the Docker images used by OSS-Fuzz
has fuzz introspector in them. Here, we provide wrapper scripts around
OSS-Fuzz to make the process of working with OSS-Fuzz easier, and also hold
scripts for making development based on testing with OSS-Fuzz easier.

## Build Fuzz Introspector with OSS-Fuzz
There are several options for building with OSS-Fuzz. These options are
provided to support different types of workflow, e.g. development and testing
purposes.

1) For trying out Fuzz Introspector you should [build with existing OSS-Fuzz purposes](#build-with-existing-oss-fuzz-purposes).
2) For testing development in `/src/fuzz_introspector` you should [build with OSS-Fuzz base clang image](#build-with-oss-fuzz-base-clang-image).
3) For testing development in the frontends (LLVM/Python Ast analyser) you should [build images completely from scratch](#build-images-completely-from-scratch).

### Build with existing OSS-Fuzz images
From within this directory, run the commands:
```
# Simply clone the most recent OSS-Fuzz version
git clone https://github.com/google/oss-fuzz

# Test a project
cd oss-fuzz
python3 ../runner.py introspector htslib 20
```

You can access the report by navigating to `http://localhost:8008/fuzz_report.html`

### Build with OSS-Fuzz base clang image
Pull the latest base-clang image from OSS-Fuzz and otherwise build the other OSS-Fuzz
images from scratch in order to pull in a custom version of fuzz introspector. This will
copy the code from the root of the fuzz introspector folder into the oss-fuzz images,
which is convenient for testing modification in e.g. `src/fuzz-introspector`.

```
# Pull the most recent OSS-Fuzz Fuzz Introspector images
./build_post_processing.sh

# Test a project
cd oss-fuzz
python3 ../runner.py introspector htslib 20
```

You can access the report by navigating to `http://localhost:8008/fuzz_report.html`

### Build images completely from scratch
This will build all images base images from scratch, and have all fuzz introspector
 diffs. This is used when developing the frontends, e.g. the LLVM pass.
```
# Build all base images from scratch
./build_all_custom_images.sh

cd oss-fuzz
python3 ../runner.py introspector htslib 30
...
```

You can access the report by navigating to `http://localhost:8008/fuzz_report.html`

# Testing before bumping OSS-Fuzz
To prevent and catch regressions we use a testing framework that verifies
the results of running fuzz-introspector on various OSS-Fuzz integrations.

The framework is designed to catch regressions of the form:
- Build issues that may be introduced, i.e. projects that are expected to succeed no longer succeeds.
- Logical regressions, focusing on if results are as expected.

The testing framework has some hard-coded boundary checks on the data
for a given project. It has to be boundaries rather than fixed values
since the data may change from run to run depending on the fuzzing
results.

To run the test suite, please perform the following steps from this
directory:

```
# Clean up any installation you may have
sudo docker system prune -a

# Rebuild images using local set up
./build_all_custom_images.sh

# Test fuzz-introspector against various projects
cd oss-fuzz
python3 ../test_projects.py
```

If the above steps end with the string "Successfully finished testing projects."
being printed, then the tests passed!

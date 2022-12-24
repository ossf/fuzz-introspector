# OSS-Fuzz integration

The easiest way to use or test the introspector is to do it by way of OSS-Fuzz.
OSS-Fuzz supports fuzz introspector and the Docker images used by OSS-Fuzz
have fuzz introspector in them. 
In this directory you can find wrapper scripts to make development and testing with Fuzz Introspector easier via using OSS-Fuzz images.

## Build Fuzz Introspector with OSS-Fuzz
There are several options for building with OSS-Fuzz. These options are
provided to support different types of workflow, e.g. development and testing
purposes.

1) For trying out Fuzz Introspector you should [build the fuzz targets with existing OSS-Fuzz images](#build-with-existing-oss-fuzz-images).
2) For testing development in `/src/fuzz_introspector` you should [build with OSS-Fuzz base clang image](#build-with-oss-fuzz-base-clang-image).
3) For testing development in the frontends (LLVM/Python AST analyser) you should [build images completely from scratch](#build-images-completely-from-scratch).

### Build with existing OSS-Fuzz images
If you want to try Fuzz Introspector on some projects from OSS-Fuzz, follow these steps:
```
# (Optional) Clone the most recent OSS-Fuzz version
git clone https://github.com/google/oss-fuzz
cd oss-fuzz

# Test a project -- From the top directory of OSS-Fuzz
python3 infra/helper.py introspector PROJECT_NAME
```

The above command builds the project using OSS-Fuzz images for coverage and introspector. To access the reports, follow the instruction at your screen where it says:
```
To browse the report, run: `python3 -m http.server 8008 --directory /path/to/reports`and navigate to localhost:8008/fuzz_report.html in your browser
```

You also can try the following different variations of introspector build for OSS-Fuzz:

```
# To download the latest public corpus for project PROJECT_NAME and use that when collecting coverage
python3 infra/helper.py introspector --public-corpora PROJECT_NAME

# To run the fuzzers for SEC seconds for corpus collection
python3 infra/helper.py introspector --seconds=SEC PROJECT_NAME

# To run introspector using the LOCAL_PATH as source code folder (for testing modifications to fuzz targets)
python3 infra/helper.py introspector PROJECT_NAME LOCAL_PATH 
```

If you are making modifications to Fuzz Introspector, then keep reading the next sections.
### Build with OSS-Fuzz base clang image
To test your new developments in the Fuzz Introspector post-processing (in `/src/fuzz_introspector`), you need to pull the latest base-clang image from OSS-Fuzz and otherwise build the other OSS-Fuzz
images from scratch. This will
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
If you have made changes in language frontend component of Fuzz Introspector (in `/frontends`), you need to build all images.
The following commands will build all images from scratch, and have all fuzz introspector
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

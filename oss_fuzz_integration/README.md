# OSS-Fuzz integration

The easiest way to test the introspector is to integrate it with OSS-Fuzz
and use the OSS-Fuzz infrastructure to help with fuzzing tasks. To do this
we have patches and scripts to automate this process. 

Notice that these scripts will pull a new version of your OSS-Fuzz Docker
images, so remember to re-`pull` images when you switch between fuzz-introspector-images and original
oss-fuzz images. The reason we have to use specific images is we need to make
a small patch to Clang due to the following issue: https://reviews.llvm.org/D77704

In order to use the OSS-Fuzz integration you must have Docker installer, as this
is a requirement for OSS-Fuzz itself.

## Build Fuzz Introspector with OSS-Fuzz
There are several options for building with OSS-Fuzz. These options are
provided to support different types of workflow, e.g. development and testing
purposes.

1) For trying out Fuzz Introspector you should [build with existing OSS-Fuzz purposes](#build-with-existing-oss-fuzz-purposes).
2) For testing development in `/src/fuzz_introspector` you should [build with OSS-Fuzz base clang image](#build-with-oss-fuzz-base-clang-image).
3) For testing development in the frontends (LLVM/Python Ast analyser) you should [build images completely from scratch](#build-images-completely-from-scratch).

### Build with existing OSS-Fuzz purposes
From within this directory, run the commands:
```
# Pull the most recent OSS-Fuzz Fuzz Introspector images
./build_oss_fuzz_pulls.sh

# Test a project
cd oss-fuzz
python3 ../runner.py introspector htslib 20
```

This will download OSS-Fuzz, pulls introspector images and tag them accordingly.

You can access the report by navigating to `http://localhost:8008/fuzz_report.html`

### Build with OSS-Fuzz base clang image
Following the above instructions, you can use the following command to perform
a complete run of the introspector, including with coverage analysis.

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

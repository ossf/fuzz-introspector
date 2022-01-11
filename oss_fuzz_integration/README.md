# OSS-Fuzz integration

The easiest way to test the introspector is to integrate it with OSS-Fuzz
and use the OSS-Fuzz infrastructure to help with fuzzing tasks. To do this
we have patches and scripts to automate this process. 

Notice that these scripts will build a new version of your OSS-Fuzz Docker
images, so preferably build things on a separate system or be prepared to
rebuild images when you switch between fuzz-introspector-images and original
oss-fuzz images. The reason we have to rebuild the images is we need to make
a small patch to Clang due to the following issue: https://reviews.llvm.org/D77704

In order to use the OSS-Fuzz integration you must have Docker installer, as this
is a requirement for OSS-Fuzz itself.

## Build the patched OSS-Fuzz
From within this directory, run the command:
```
./build_patched_oss_fuzz.sh
```

This will download OSS-Fuzz, apply our patches and build the Docker images.

## Run the introspector
Following the above instructions, you can use the following command to perform
a complete run of the introspector, including with coverage analysis.


```
cd oss-fuzz
../run_both.sh htslib 30
...
If all worked, then you should be able to start a webserver at port 8008 in ./corpus-0/inspector-report/
Serving HTTP on 0.0.0.0 port 8008 (http://0.0.0.0:8008/) ...
```

You can now navigate to `http://localhost:8008/fuzz_report.html`

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

## Build the patched OSS-Fuzz
From within this directory, run the command:
```
./prepare_images.sh
```

This will download OSS-Fuzz, pulls introspector images and tag them accordingly.

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

When you run above command, the OSS-Fuzz coverage run will start a webserver (like following logs) to
serve coverage reports. You need to kill it using Ctrl-C to let the rest of
script work correctly on your local machine.

```
[ INFO] Index file for html report is generated as:
"file:///out/report_target/hts_open_fuzzer/linux/index.html".
Serving the report on http://127.0.0.1:8008/linux/index.html
Serving HTTP on 0.0.0.0 port 8008 (http://0.0.0.0:8008/) ...
```
You can now navigate to `http://localhost:8008/fuzz_report.html`

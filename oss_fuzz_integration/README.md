# OSS-Fuzz integration

The easiest way to test the introspector is to integrate it with OSS-Fuzz
and use the OSS-Fuzz infrastructure to help with fuzzing tasks. To do this
we have patches and scripts to automate this process. 

Notice that these scripts will build a new version of your OSS-Fuzz Docker
images, so preferably build things on a separate system or be prepared to
rebuild images when you switch between fuzz-introspector-images and original
oss-fuzz images. The reason we have to rebuild the images is we need to make
a small patch to Clang due to the following issue: https://reviews.llvm.org/D77704

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
cd corpus-0/report
python3 -m http.server 5001 &
cd ../../
cd build/out/htslib/inspector-tmp
python3 -m http.server 5002
```

You can now navigate to `http://localhost:5002/fuzz_report.html`

You should start the first webserver (coverage data) on port 5001 as shown
above. Otherwise there will be broken links in the introspector report.

Notice that when running these commands the `run_both.sh` script will use
OSS-Fuzz to generate coverage. This will result in a webserver being launched
and you will have to exit that server. So, when the following output happens
please use ctrl-c to exit it:

```
[2021-10-06 15:56:32,752 INFO] Finding shared libraries for targets (if any).
[2021-10-06 15:56:32,759 INFO] Finished finding shared libraries for targets.
[2021-10-06 15:56:32,920 DEBUG] Finished generating per-file code coverage summary.
[2021-10-06 15:56:32,920 DEBUG] Generating file view html index file as: "/out/report/linux/file_view_index.html".
[2021-10-06 15:56:32,931 DEBUG] Finished generating file view html index file.
[2021-10-06 15:56:32,931 DEBUG] Calculating per-directory coverage summary.
[2021-10-06 15:56:32,932 DEBUG] Finished calculating per-directory coverage summary.
[2021-10-06 15:56:32,932 DEBUG] Writing per-directory coverage html reports.
[2021-10-06 15:56:33,000 DEBUG] Finished writing per-directory coverage html reports.
[2021-10-06 15:56:33,000 DEBUG] Generating directory view html index file as: "/out/report/linux/directory_view_index.html".
[2021-10-06 15:56:33,000 DEBUG] Finished generating directory view html index file.
[2021-10-06 15:56:33,000 INFO] Index file for html report is generated as: "file:///out/report/linux/index.html".
Serving the report on http://127.0.0.1:8008/linux/index.html
Serving HTTP on 0.0.0.0 port 8008 (http://0.0.0.0:8008/) ...
```

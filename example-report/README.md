# Example report
This folder contains an example report.

To see the report in your own browser simply unzip the report.zip file, start a webserver in the unzipped folder `python3 -m http.server 8001` and then navigate to `http://localhost:8001/fuzz_report.html` from your browser.

To reproduce this report you can follow the instructions of OSS-Fuzz integration and then launching an analysis using `run_both.sh` with the params `htslib 400` (analyse the htslib project and run a fuzzer for 400 seconds).

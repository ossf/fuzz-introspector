For c / c++ / python
[retrieve_project_link.py]
This python script retrieves all the project's link that exists in the Google Cloud

[retrieve_files.py]
This script retrieves the newest all_functions.js and summary.json from the cloud server following the link retrieved by retrieve_project_link.py
The all_functions.js and summary.json are renamed to the project name and stored in all_funtions/ and summary_json/ respectively for each project.

For JVM
[test_project.py] (in fuzz-introspector/oss_fuzz_integration)
The test_project.py script will test the project implementation, and also copy the all_functions.js and summary.json to the above-mentioned folders.

[proj/]
This directory has config files for each language. Each file contains the list of the project for each language for testing.

[check_files.py]
According to the project list in the proj/<lang> folder, analyse its all_functions.js and summary.json file and generate the enumerative testing result
in csv format.

[run.sh]
A wrapper script to run all the above python scripts at once for c / c++ / python.

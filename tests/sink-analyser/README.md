For c / c++ / python
[retrieve_project_link.py]
This python script grab all the project's link exists in the Google Cloud

[retrieve_files.py]
According to the link grabbed by the above script. This script grab the newest all_functions.js and summary.json from the cloud server.
The all_functions.js and summary.json are renamed to the project name and stored in all_funtions/ and summary_json/ respectively for each
project.

For JVM
[test_project.py] (in fuzz-introspector/oss_fuzz_integration)
The test_project.py script will test the project implementation, and also copy the all_functions.js and summary.json to the above respective 
folders.

[proj/]
This directory has config file for each language. Each file contains the list of project for each language for testing.

[check_files.py]
According to the project list in the proj/<lang> folder, analyse its all_functions.js and summary.json file and generate enuemrative testing result.

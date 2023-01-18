Compare introspector reports
============================

Fuzz Introspector comes with a ``diff`` command to differentiate two Fuzz
Introspector runs. This is achieved by way of the ``summary.json`` file which
Fuzz Introspector produces, and holds a lot of the data Fuzz Introspector
generates in json format.

The ``diff`` command simply takes two ``summary.json`` files as arguments, and
will highlight important differences, e.g. coverage and reachability, between
the reports.

This user guide will show how to use the ``diff`` command to compare two fuzzing reports.
This is used when assessing whether any regression or improvements has happened, for example
while developing extensions to a given fuzzing suite.

The current diffing supported by Fuzz Introspector is not integrated into
OSS-Fuzz yet. As such, to use this feature you need to use a local recent
version of Fuzz Introspector. For the sake of completeness we will assume
the set up achieved using the following commands:

.. code-block:: bash

   # Get a local Fuzz Introspector code, and install Python dependencies.
   git clone https://github.com/ossf/fuzz-introspector
   cd fuzz-introspector
   git submodule init
   git submodule update

   python3 -m virtualenv .venv
   . .venv/bin/activate
   pip3 install -r ./requirements.txt

   # Clone OSS-Fuzz
   cd oss_fuzz_integration
   ./build_post_processing.sh

   cd oss-fuzz

The following assume you're in the oss-fuzz directory as at the end of the
commands above.

The next step is to generate two Fuzz Introspector reports, where there will
be a difference in the results in the report. There are two different results
that we're often interested in knowing: increase of code coverage and increase
of reachability.


Example of runtime coverage improvements
----------------------------------------
The following assumes you're in the ``oss-fuzz`` directory as generated above
and that the virtual environment is activated.

In the context of code coverage, we will run the exact same project twice
using a different amount of seconds for the fuzzers.

.. code-block:: bash

   # Generate an introspector report based on 10 seconds of runtime.
   # Then save the generated JSON file and clean up.
   python3 infra/helper.py introspector htslib --seconds=10
   cp ./build/out/htslib/inspector/summary.json summary_first_run.json
   sudo rm -rf ./build

   # Do another run for 300 seconds
   python3 infra/helper.py introspector htslib --seconds=300
   cp ./build/out/htslib/inspector/summary.json summary_second_run.json

At this point we have two ``.json`` files with data from two Fuzz Introspector
runs. The difference between the Fuzz Introspector runs is that one is based
on a corpus generated over 10 seconds and the other is based on a corpus
generated over 300 seconds.

We can now compare the two runs using the Fuzz Introspector ``diff`` command:

.. code-block:: console

   $ python3 ../../src/main.py diff \
     --report1 ./summary_first_run.json \
     --report2 ./summary_second_run.json

   INFO:__main__:Running fuzz introspector post-processing
   Report 2 has similar Total complexity to report 1 - {report 1: 16627 / report 2: 16627})

   ## Code coverge comparison
   The following functions report 2 has decreased code coverage:
   Report 2 has less coverage {  64.0 vs   46.0} for bcf_hdr_read

   The following functions report 2 has increased code coverage:
   Report 2 has more coverage {   0.0 vs   60.0} for sam_hrecs_find_key
   Report 2 has more coverage {   0.0 vs  100.0} for TYPEKEY
   Report 2 has more coverage {   0.0 vs  78.04} for kh_put_sam_hrecs_t
   Report 2 has more coverage {   0.0 vs   80.0} for sam_hrecs_global_list_add
   Report 2 has more coverage {   0.0 vs   29.8} for sam_hrecs_update_hashes
   Report 2 has more coverage {   0.0 vs  54.83} for kh_resize_sam_hrecs_t
   Report 2 has more coverage {   0.0 vs  100.0} for isalpha_c
   Report 2 has more coverage {   0.0 vs   87.5} for sam_hrecs_error
   Report 2 has more coverage {  40.0 vs   60.0} for sam_hdr_fill_hrecs
   Report 2 has more coverage {   0.0 vs  100.0} for redact_header_text
   Report 2 has more coverage { 80.64 vs  83.87} for sam_hrecs_free
   Report 2 has more coverage {   0.0 vs  92.23} for sam_hrecs_parse_lines
   Report 2 has more coverage {   0.0 vs  19.35} for sam_hdr_update_target_arrays
   Report 2 has more coverage {   0.0 vs  78.57} for sam_hrecs_rebuild_lines
   Report 2 has more coverage {   0.0 vs  100.0} for build_header_line
   Report 2 has more coverage { 34.28 vs  37.14} for sam_hdr_count_lines
   Report 2 has more coverage {   0.0 vs  84.21} for sam_hdr_add_lines
   Report 2 has more coverage {   0.0 vs  100.0} for ks_release
   Report 2 has more coverage { 55.55 vs  88.88} for sam_hrecs_rebuild_text
   Report 2 has more coverage { 30.55 vs  52.77} for hseek
   Report 2 has more coverage {   0.0 vs  100.0} for hgetc2
   Report 2 has more coverage { 66.48 vs  81.86} for hts_detect_format2
   Report 2 has more coverage {   0.0 vs  100.0} for decompress_peek_gz
   Report 2 has more coverage {   0.0 vs   65.0} for parse_version
   Report 2 has more coverage {   0.0 vs  68.29} for hts_resize_array_
   Report 2 has more coverage { 67.92 vs  92.45} for hts_close
   Report 2 has more coverage {  76.1 vs   82.3} for hts_hopen
   Report 2 has more coverage {   0.0 vs  100.0} for kh_destroy_s2i
   Report 2 has more coverage {   0.0 vs  100.0} for kh_init_s2i
   Report 2 has more coverage {   0.0 vs  34.84} for sam_parse1
   Report 2 has more coverage {   0.0 vs  66.66} for possibly_expand_bam_data
   Report 2 has more coverage {   0.0 vs  100.0} for parse_sam_flag
   Report 2 has more coverage {   0.0 vs  46.42} for hts_str2uint
   Report 2 has more coverage {   0.0 vs  100.0} for known_stderr
   Report 2 has more coverage {   0.0 vs  100.0} for valid_sam_header_type
   Report 2 has more coverage {   0.0 vs  100.0} for warn_if_known_stderr
   Report 2 has more coverage { 57.74 vs  63.38} for sam_format1_append
   Report 2 has more coverage { 54.91 vs  67.21} for fastq_parse1
   ...
   ...

The output of the ``diff`` command shows us the difference achieved, namely,
that for larger amounts of functions the second report (with the longer run)
has more code coverage.


Example of reachability differences
-----------------------------------

In the context of reachability we need more effort than simply running the
same project twice with a different number of seconds (as done in
:ref:`Example of runtime coverage improvements`). In order to display
reachability differences, we need to change the actual code, as the reachability
analysis is based on static analysis.

To display reachability differences we will use the ``libarchive`` OSS-Fuzz
integration. We will first run it with a limited version of the setup, and then
run it with the full version of the setup.

First, comment out the lines at https://github.com/google/oss-fuzz/blob/a8cb9370f0dddf33111b1a7ce6d715633d5400df/projects/libarchive/libarchive_fuzzer.cc#L39-L73
Then, we build the introspector report using a 1 second runtime:

.. code-block:: bash

   # Generate an introspector report based on 1 second runtime with our
   # modified libarchive fuzzer.
   python3 infra/helper.py introspector libarchive --seconds=1
   cp ./build/out/libarchive/inspector/summary.json libarchive_first_run.json
   sudo rm -rf ./build


Then, we remove the comments from above so we have the original fuzzer,
and do a similar run:

.. code-block:: bash

   python3 infra/helper.py introspector libarchive --seconds=1
   cp ./build/out/libarchive/inspector/summary.json libarchive_second_run.json

At this point we have collected the two reports, each with different fuzzers.
We now run our ``diff`` command on the two reports:

.. code-block:: console

   $ python3 ../../src/main.py diff \
     --report1 ./libarchive_first_run.json \
     --report2 ./libarchive_second_run.json

    INFO:__main__:Running fuzz introspector post-processing
    Report 2 has a larger Total complexity than report 1 - {report 1: 9763 / report 2: 9787})

    ## Code coverge comparison
    ...
    ...

    ## Reachability comparison
    The following functions are only reachable in report 1:
    - All functions reachable in report 1 are reachable in report 2

    The following functions are only reachable in report 2:
    archive_read_data
    mbrtowc
    get_current_oemcp
    default_iconv_charset
    nl_langinfo
    get_current_codepage
    archive_string_conversion_from_charset
    archive_strncpy_l
    free_sconv_object
    archive_wstring_append_from_mbs
    iconv_close
    archive_strncat_l
    utf16nbytes
    mbsnbytes
    get_current_charset
    archive_mstring_get_mbs
    archive_mstring_get_wcs
    archive_mstring_get_utf8
    archive_string_conversion_to_charset
    archive_read_data_block
    archive_read_next_header
    archive_entry_digest
    archive_entry_is_encrypted
    archive_entry_is_metadata_encrypted
    archive_entry_is_data_encrypted
    archive_entry_uid
    archive_entry_size
    gnu_dev_makedev
    archive_entry_pathname_w
    archive_entry_pathname_utf8
    archive_entry_pathname
    archive_entry_mtime
    archive_entry_gid
    archive_entry_filetype
    archive_entry_dev
    archive_entry_ctime
    archive_entry_birthtime
    archive_entry_atime
    INFO:__main__:Ending fuzz introspector post-processing

We can observe that indeed a lot more functions are reachable in the run, which
is the verison of the fuzzer that has no code commented out. Furthermore,
we notice that many of the functions that are reachable in the second
report correspond to functions that we commented out in the first run.

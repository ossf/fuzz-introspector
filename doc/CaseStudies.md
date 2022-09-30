# [xpdf](https://storage.googleapis.com/oss-fuzz-introspector/xpdf/inspector-report/20220321/fuzz_report.html)
Introspector report: [link](https://storage.googleapis.com/oss-fuzz-introspector/xpdf/inspector-report/20220321/fuzz_report.html)

A [previous blog post by Project Zero](https://googleprojectzero.blogspot.com/2021/12/a-deep-dive-into-nso-zero-click.html)
details a vulnerability exploited by NSO to hack iOS users in xpdf. This vulnerability is in the `JBIG2Stream::readTextRegionSeg`
function in xpdf.

xpdf is integrated into OSS-Fuzz, but the existing fuzzing did not cover [`JBIG2Stream::readTextRegionSeg`](https://storage.googleapis.com/oss-fuzz-coverage/xpdf/reports/20220331/linux/src/xpdf-4.03/xpdf/JBIG2Stream.cc.html#L1953).
As shown in Figure 1, in the "Optimal target analysis" section of Fuzz Introspector report for xpdf, the
second function suggested is `JBIG2Stream::reset()`.

The main function called by `JBIG2Stream::reset()` is `JBIG2Stream::readSegments`.
`readSegments` actually calls the vulnerable function `readTextRegionSeg`.

So the call tree for this fuzz target would be: 
```
JBIG2Stream::reset()
	readSegments()
		readTextRegionSeg() // vulnerable function.
```

<img width="754" alt="image3" src="https://user-images.githubusercontent.com/759062/165666092-1415fa68-4a9f-4b8f-afad-b18f45d67bcc.png">


<p align="center">Figure 1: List of suggested targets for xpdf</p>

Based on this suggestion, we wrote a [new fuzzer](https://github.com/google/oss-fuzz/blob/master/projects/xpdf/fuzz_JBIG2.cc) to target `JBIG2Stream::reset()`. As visible in the latest coverage reports, OSS-Fuzz is now exercising the vulnerable
function [`JBIG2stream::readTextRegionSeg()`](https://storage.googleapis.com/oss-fuzz-coverage/xpdf/reports-by-target/20220412/fuzz_JBIG2/linux/src/xpdf-4.03/xpdf/JBIG2Stream.cc.html#L1953).
This proves the usefulness of Fuzz Introspector in identifying and suggesting interesting new fuzz targets.

# [jsonnet](https://oss-fuzz-introspector.storage.googleapis.com/jsonnet/inspector-report/20220315/fuzz_report.html)

Introspector report: [link](https://oss-fuzz-introspector.storage.googleapis.com/jsonnet/inspector-report/20220315/fuzz_report.html)

Fuzz Introspector provides a [call-tree overview](https://oss-fuzz-introspector.storage.googleapis.com/jsonnet/inspector-report/20220315/fuzz_report.html#call_tree_0) for each fuzz target (Figure 2).
This [overview](https://github.com/ossf/fuzz-introspector/blob/main/doc/Glossary.md#call-tree-overview)
shows the fuzz target coverage by color coding the call instructions. The red shaded areas are where the target fails to cover.
As Figure 2 shows, jsonnet fuzz target fails to cover a big chunk of code.

![image2](https://user-images.githubusercontent.com/759062/165666474-6d631019-8cb5-42ae-8e5b-94d8c3dbbc73.png)

<p align="center">Figure 2: Fuzz target coverage for jsonnet before adding new targets</p>

Looking at the Fuzz blocker table (Figure 3), the top blocker is in  the [`jsonnet_evaluate_snippet_aux()`](https://storage.googleapis.com/oss-fuzz-coverage/jsonnet/reports/20220314/linux/src/jsonnet/core/libjsonnet.cpp.html#L482) funcion,
where a [switch statement](https://storage.googleapis.com/oss-fuzz-coverage/jsonnet/reports/20220314/linux/src/jsonnet/core/libjsonnet.cpp.html#L501) branches on an argument of type EvalKind. 

![image3](https://user-images.githubusercontent.com/19780488/166503231-d698f922-95ea-45d4-b93f-7d40477d1edd.png)

<p align="center">Figure 3: Top fuzz blockers for jsonnet</p>

Looking into the fuzz target call tree reveals that the argument of type `EvalKind`
is always set to a static value (`REGULAR` in this case).
It means that the existing fuzz target has no way to explore other cases of the switch statement. 

To improve the fuzzing coverage, one could quickly conclude that we need fuzz targets to
make a call to [`jsonnet_evaluate_snippet_aux()`](https://storage.googleapis.com/oss-fuzz-coverage/jsonnet/reports/20220314/linux/src/jsonnet/core/libjsonnet.cpp.html#L482)
with other possible values of `Evalkind`. To this end we wrote two new fuzz targets to do
this via the provided interfaces
[`jsonnet_evaluate_snippet_multi()`](https://storage.googleapis.com/oss-fuzz-coverage/jsonnet/reports/20220314/linux/src/jsonnet/core/libjsonnet.cpp.html#L669)
and  [`jsonnet_evaluate_snippet_stream()`](https://storage.googleapis.com/oss-fuzz-coverage/jsonnet/reports/20220314/linux/src/jsonnet/core/libjsonnet.cpp.html#L678). 
This way we were able to unblock the jsonnet fuzzer and increase the call tree coverage dramatically (Figure 4). 

![image4](https://user-images.githubusercontent.com/759062/165666703-c9ab3fde-4629-49db-bd2b-f2d6e4fc8b03.png)

<p align="center">Figure 4: Fuzz target coverage for jsonnet after adding new targets</p>

# [file](https://storage.googleapis.com/oss-fuzz-introspector/file/inspector-report/20220329/fuzz_report.html)
Introspector report: [link](https://storage.googleapis.com/oss-fuzz-introspector/file/inspector-report/20220329/fuzz_report.html)

[MWDB](https://github.com/CERT-Polska/mwdb-core) uses [file](https://github.com/file/file)
on malware samples, which is [worrying](https://github.com/CERT-Polska/mwdb-core/issues/671) to say the least.

After sending [a]( https://github.com/google/oss-fuzz/pull/8536)
[couple of](https://github.com/google/oss-fuzz/pull/8535)
[pull requests](https://github.com/google/oss-fuzz/pull/8533) to tackle the low-hanging fruits,
the [Remaining optimal interesting
functions](https://storage.googleapis.com/oss-fuzz-introspector/file/inspector-report/20220901/fuzz_report.html#Analyses-and-suggestions)
section showed that an awful lot of functions in the `readelf.c` file weren't touched
at all by the fuzzers.

Looking at the [Fuzz blockers](https://storage.googleapis.com/oss-fuzz-introspector/file/inspector-report/20220901/fuzz_report.html#fuzz_blocker0),
`file_tryelf` was likely the functions that should be called, and by checking out the
[coverage of the relevant file](https://storage.googleapis.com/oss-fuzz-coverage/file/reports/20220901/linux/src/file/src/funcs.c.html#L421),
the culprit was that `file` needs to be passed data via a proper file descriptor
to exercise its elf-related codepath, and thus a file-based fuzzer was [promptly added](https://github.com/google/oss-fuzz/pull/8542),
[bumping the coverage close to 90%]( https://storage.googleapis.com/oss-fuzz-introspector/file/inspector-report/20220930/fuzz_report.html ).

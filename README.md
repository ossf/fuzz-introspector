[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ossf/fuzz-introspector/badge)](https://api.securityscorecards.dev/projects/github.com/ossf/fuzz-introspector)

# Fuzz introspector

Fuzz introspector is a tool to help fuzzer developers to get an understanding of their fuzzer’s performance 
and identify any potential blockers. Fuzz introspector aggregates the fuzzers’ functional data like coverage,
hit frequency, entry points, etc to give the developer a birds eye view of their fuzzer. This helps with 
identifying fuzz bottlenecks and blockers and eventually helps in developing better fuzzers.

Fuzz-introspector aims to improve fuzzing experience of a project by guiding on whether you should:
- introduce new fuzzers to a fuzz harness
- modify existing fuzzers to improve the quality of your harness.

## Indexing OSS-Fuzz projects

[Open Source Fuzzing Introspection](https://introspector.oss-fuzz.com) provides introspection capabilities to [OSS-Fuzz](https://github.com/google/oss-fuzz) projects and is powered by Fuzz Introspector. This page gives macro insights into the fuzzing of open source projects.

On this page you'll see a list of all the projects that are currently analysed by Fuzz Introspector:
- [Table of projects with Fuzz Introspector analysis](https://introspector.oss-fuzz.com/projects-overview)
- Examples, with links in profile to latest Fuzz Introspector analysis:
  - [Liblouis / C](https://introspector.oss-fuzz.com/project-profile?project=liblouis)
  - [htslib / C](https://introspector.oss-fuzz.com/project-profile?project=htslib)
  - [brotli / C++](https://introspector.oss-fuzz.com/project-profile?project=brotli)
  - [idna / python](https://introspector.oss-fuzz.com/project-profile?project=idna)
  - [junrar / java](https://introspector.oss-fuzz.com/project-profile?project=junrar)


## Docs and demonstrations
The main Fuzz Introspector documentation is available here: https://fuzz-introspector.readthedocs.io This documentation includes user guides, OSS-Fuzz instructions, tutorials, development docs and more.
Additionally, there is more information:
- [Video demonstration](https://www.youtube.com/watch?v=cheo-liJhuE)
- [List of Case studies](doc/CaseStudies.md)
- [Screenshots](doc/ExampleOutput.md)
- [Feature list](doc/Features.md)
- Try yourself:
  - [Use with OSS-Fuzz](oss_fuzz_integration#build-fuzz-introspector-with-oss-fuzz) (Recommended)
  - [Use without OSS-Fuzz](doc/LocalBuild.md)

## Architecture
The workflow of fuzz-introspector can be visualised as follows:
![Functions table](/doc/img/fuzz-introspector-architecture.png)

A more detailed description is available in [doc/Architecture](/doc/Architecture.md)

## Contribute
### Code of Conduct
Before contributing, please follow our [Code of Conduct](CODE_OF_CONDUCT.md).

### Connect with the Fuzzing Community
If you want to get involved in the Fuzzing community or have ideas to chat about, we discuss
this project in the
[OSSF Security Tooling Working Group](https://github.com/ossf/wg-security-tooling)
meetings.

More specifically, you can attend Fuzzing Collaboration meeting (monthly on
the first Tuesday 10:30am - 11:30am PST
[Calendar](https://calendar.google.com/calendar?cid=czYzdm9lZmhwNWk5cGZsdGI1cTY3bmdwZXNAZ3JvdXAuY2FsZW5kYXIuZ29vZ2xlLmNvbQ),
[Zoom
Link](https://zoom.us/j/99960722134?pwd=ZzZqdzY1eG9tMzQxWFI1Z0RhTkUxZz09)).

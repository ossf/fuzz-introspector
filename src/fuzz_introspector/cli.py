# Copyright 2024 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Command-line interface"""

import argparse
import logging
import os
import sys

from fuzz_introspector import commands, constants

sys.setrecursionlimit(10000)

logger = logging.getLogger(name=__name__)
LOG_FMT = ('%(asctime)s.%(msecs)03d %(levelname)s '
           '%(module)s - %(funcName)s: %(message)s')


def get_cmdline_parser() -> argparse.ArgumentParser:
    """Parse the commandline"""
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    light_parser = subparsers.add_parser(
        "light",
        help="Perform light analysis of project. This involves no compilaiton.",
    )
    light_parser.add_argument("--language",
                              type=str,
                              default="c-cpp",
                              help="Language of project")

    full_parser = subparsers.add_parser(
        'full', help='Analyse folder and generate HTML report and analyses.')
    full_parser.add_argument('--target-dir',
                             type=str,
                             help='Directory holding source to analyse.',
                             required=True)
    full_parser.add_argument('--language',
                             type=str,
                             help='Programming of the source code to analyse.',
                             choices=constants.LANGUAGES_SUPPORTED)
    full_parser.add_argument('--out-dir',
                             default='',
                             type=str,
                             help='Folder to store analysis results.')
    full_parser.add_argument('--name',
                             default='no-name',
                             type=str,
                             help='Name of the report.')
    full_parser.add_argument('--coverage-url',
                             default='/covreport/linux',
                             type=str,
                             help='Base coverage URL.')
    full_parser.add_argument(
        '--module-only',
        action='store_true',
        help='Will dump program analysis data even if not harness exists.')

    # Report generation command
    report_parser = subparsers.add_parser(
        "report",
        help="generate fuzz-introspector HTML report",
    )
    report_parser.add_argument("--target-dir",
                               type=str,
                               help="Directory where the data files are",
                               required=True)
    report_parser.add_argument("--coverage-url",
                               type=str,
                               help="URL with coverage information",
                               default="/covreport/linux")
    report_parser.add_argument("--analyses",
                               nargs="+",
                               default=[
                                   "OptimalTargets", "RuntimeCoverageAnalysis",
                                   "FuzzEngineInputAnalysis",
                                   "FilePathAnalyser", "MetadataAnalysis",
                                   "AnnotatedCFG", "FrontendAnalyser"
                               ],
                               help="""
            Analyses to run. Available options:
            AnnotatedCFG, BugDigestorAnalysis, FuzzCalltreeAnalysis,
            FuzzDriverSynthesizerAnalysis, FuzzEngineInputAnalysis,
            FilePathAnalyser, ThirdPartyAPICoverageAnalyser,
            MetadataAnalysis, OptimalTargets, RuntimeCoverageAnalysis,
            SinkCoverageAnalyser, FrontendAnalyser
        """)
    report_parser.add_argument("--enable-all-analyses",
                               action='store_true',
                               default=False,
                               help="Enables all analyses")
    report_parser.add_argument("--correlation-file",
                               type=str,
                               default="",
                               help="File with correlation data")
    report_parser.add_argument("--name",
                               type=str,
                               default="",
                               help="Name of project")
    report_parser.add_argument("--language",
                               type=str,
                               default="c-cpp",
                               help="Language of project")
    report_parser.add_argument(
        "--output-json",
        nargs="+",
        default=["FuzzEngineInputAnalysis"],
        help="State which analysis requires separate json report output")

    # Command for correlating binary files to fuzzerLog files
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="correlate executable files to fuzzer introspector logs")
    correlate_parser.add_argument(
        "--binaries-dir",
        type=str,
        required=True,
        help="Directory with binaries to scan for Fuzz introspector tags")

    # Command for diffing two Fuzz Introspector reports
    diff_parser = subparsers.add_parser(
        'diff', help='Diff two reports to identify improvements/regressions')
    diff_parser.add_argument('--report1',
                             type=str,
                             required=True,
                             help='Path to the first report')
    diff_parser.add_argument('--report2',
                             type=str,
                             required=True,
                             help='Path to the second report')

    # Standalone analyser
    analyse_parser = subparsers.add_parser(
        'analyse',
        help='Standlone analyser commands to run on the target project.')

    analyser_parser = analyse_parser.add_subparsers(dest='analyser',
                                                    required=True,
                                                    help="""
        Available analyser:
        SourceCodeLineAnalyser FarReachLowCoverageAnalyser
        PublicCandidateAnalyser FrontendAnalyser""")

    source_code_line_analyser_parser = analyser_parser.add_parser(
        'SourceCodeLineAnalyser',
        help=('Provide information in out-dir/function.json for the function'
              ' found in the given target file and line number'))
    source_code_line_analyser_parser.add_argument(
        '--source-file',
        default='',
        type=str,
        help='Target file path or name for SourceCodeLineAnalyser')
    source_code_line_analyser_parser.add_argument(
        '--source-line',
        default=-1,
        type=int,
        help='Target line for SourceCodeLineAnalyser')
    source_code_line_analyser_parser.add_argument(
        '--target-dir',
        type=str,
        help='Directory holding source to analyse.',
        required=True)
    source_code_line_analyser_parser.add_argument(
        '--language',
        type=str,
        help='Programming of the source code to analyse.',
        choices=constants.LANGUAGES_SUPPORTED)
    source_code_line_analyser_parser.add_argument(
        '--out-dir',
        default='',
        type=str,
        help='Folder to store analysis results.')

    far_reach_low_coverage_analyser_parser = analyser_parser.add_parser(
        'FarReachLowCoverageAnalyser',
        help=('Provide interesting functions in the project that '
              'are good targets for fuzzing with low runtime coverage.'))

    far_reach_low_coverage_analyser_parser.add_argument(
        '--exclude-static-functions',
        action='store_true',
        help='Excluding static functions in the analysing result.')
    far_reach_low_coverage_analyser_parser.add_argument(
        '--only-referenced-functions',
        action='store_true',
        help='Excluding non-referenced functions in the analysing result.')
    far_reach_low_coverage_analyser_parser.add_argument(
        '--only-header-functions',
        action='store_true',
        help=('Excluding functions without header declaration in the '
              'analysing result.'))
    far_reach_low_coverage_analyser_parser.add_argument(
        '--only-interesting-functions',
        action='store_true',
        help=('Excluding functions without interesting fuzz keywords, like'
              'parse or deserialise'))
    far_reach_low_coverage_analyser_parser.add_argument(
        '--only-easy-fuzz-params',
        action='store_true',
        help=('Only include functions with easy fuzz parameters, like char*'
              'int, or string'))
    far_reach_low_coverage_analyser_parser.add_argument(
        '--max-functions',
        default=30,
        type=int,
        help='The max number of functions returned by this analysis.')
    far_reach_low_coverage_analyser_parser.add_argument(
        '--min-complexity',
        default=0,
        type=int,
        help='The min cyclomatic complexity of the functions returned.')
    far_reach_low_coverage_analyser_parser.add_argument(
        '--target-dir',
        type=str,
        help='Directory holding source to analyse.',
        required=True)
    far_reach_low_coverage_analyser_parser.add_argument(
        '--language',
        type=str,
        help='Programming of the source code to analyse.',
        choices=constants.LANGUAGES_SUPPORTED)
    far_reach_low_coverage_analyser_parser.add_argument(
        '--out-dir',
        default='',
        type=str,
        help='Folder to store analysis results.')

    public_candidate_analyser_parser = analyser_parser.add_parser(
        'PublicCandidateAnalyser',
        help=('Provide publicly accessible non-standard library functions '
              'for the project that are good targets for fuzzing.'))

    public_candidate_analyser_parser.add_argument(
        '--target-dir',
        type=str,
        help='Directory holding source to analyse.',
        required=True)
    public_candidate_analyser_parser.add_argument(
        '--language',
        type=str,
        help='Programming of the source code to analyse.',
        choices=constants.LANGUAGES_SUPPORTED)
    public_candidate_analyser_parser.add_argument(
        '--out-dir',
        default='',
        type=str,
        help='Folder to store analysis results.')

    frontend_analyser_parser = analyser_parser.add_parser(
        'FrontendAnalyser',
        help=('Do a second run of the frontend and provide analysis '
              'of public test files found in the project.'))

    frontend_analyser_parser.add_argument(
        '--target-dir',
        type=str,
        help='Directory holding source to analyse.',
        required=True)
    frontend_analyser_parser.add_argument(
        '--language',
        type=str,
        help='Programming language of the source code to analyse.',
        choices=constants.LANGUAGES_SUPPORTED)
    frontend_analyser_parser.add_argument(
        '--out-dir',
        default='',
        type=str,
        help='Folder to store analysis results.')

    return parser


def set_logging_level() -> None:
    """Sets logging level."""
    if os.environ.get('FUZZ_LOGLEVEL', 'info') == 'debug':
        logging.basicConfig(
            level=logging.DEBUG,
            format=LOG_FMT,
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    else:
        logging.basicConfig(
            level=logging.INFO,
            format=LOG_FMT,
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    logger.debug("Logging level set")


def main() -> int:
    """Main CLI entrypoint."""
    set_logging_level()

    parser = get_cmdline_parser()
    args = parser.parse_args()

    logger.info("Running fuzz introspector post-processing")
    if args.command == 'report':
        return_code, _ = commands.run_analysis_on_dir(
            args.target_dir, args.coverage_url, args.analyses,
            args.correlation_file, args.enable_all_analyses, args.name,
            args.language, args.output_json)
        logger.info("Ending fuzz introspector report generation")
    elif args.command == 'correlate':
        return_code = commands.correlate_binaries_to_logs(args.binaries_dir)
    elif args.command == 'diff':
        return_code = commands.diff_two_reports(args.report1, args.report2)
    elif args.command == 'light':
        return_code = commands.light_analysis(args)
    elif args.command == 'full':
        return_code = commands.end_to_end(args)
    elif args.command == 'analyse':
        return_code = commands.analyse(args)
    else:
        return_code = constants.APP_EXIT_ERROR
    logger.info("Ending fuzz introspector post-processing")
    sys.exit(return_code)


if __name__ == "__main__":
    main()

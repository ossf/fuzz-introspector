# Copyright 2021 Fuzz Introspector Authors
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

logger = logging.getLogger(name=__name__)


def get_cmdline_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    # Report generation command
    report_parser = subparsers.add_parser(
        "report",
        help="generate fuzz-introspector HTML report",
    )
    report_parser.add_argument(
        "--target_dir",
        type=str,
        help="Directory where the data files are",
        required=True
    )
    report_parser.add_argument(
        "--coverage_url",
        type=str,
        help="URL with coverage information",
        default="/covreport/linux"
    )
    report_parser.add_argument(
        "--analyses",
        nargs="+",
        default=[
            "OptimalTargets",
            "RuntimeCoverageAnalysis",
            "FuzzEngineInputAnalysis",
            "FilePathAnalyser",
            "MetadataAnalysis"
        ],
        help="""
            Analyses to run. Available options:
            OptimalTargets, FuzzEngineInput, ThirdPartyAPICoverageAnalyser
        """
    )
    report_parser.add_argument(
        "--enable-all-analyses",
        action='store_true',
        default=False,
        help="Enables all analyses"
    )
    report_parser.add_argument(
        "--correlation_file",
        type=str,
        default="",
        help="File with correlation data"
    )
    report_parser.add_argument(
        "--name",
        type=str,
        default="",
        help="Name of project"
    )
    report_parser.add_argument(
        "--language",
        type=str,
        default="c-cpp",
        help="Language of project"
    )

    # Command for correlating binary files to fuzzerLog files
    correlate_parser = subparsers.add_parser(
        "correlate",
        help="correlate executable files to fuzzer introspector logs"
    )
    correlate_parser.add_argument(
        "--binaries_dir",
        type=str,
        required=True,
        help="Directory with binaries to scan for Fuzz introspector tags"
    )

    return parser


def set_logging_level() -> None:
    if os.environ.get("FUZZ_LOGLEVEL"):
        level = os.environ.get("FUZZ_LOGLEVEL")
        if level == "debug":
            logging.basicConfig(level=logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.INFO)
    logger.debug("Logging level set")


def main() -> int:
    set_logging_level()

    parser = get_cmdline_parser()
    args = parser.parse_args()

    logger.info("Running fuzz introspector post-processing")
    if args.command == 'report':
        return_code = commands.run_analysis_on_dir(
            args.target_dir,
            args.coverage_url,
            args.analyses,
            args.correlation_file,
            args.enable_all_analyses,
            args.name,
            args.language
        )
        logger.info("Ending fuzz introspector report generation")
    elif args.command == 'correlate':
        return_code = commands.correlate_binaries_to_logs(args.binaries_dir)
    else:
        return_code = constants.APP_EXIT_ERROR
    logger.info("Ending fuzz introspector post-processing")
    sys.exit(return_code)


if __name__ == "__main__":
    main()

# Copyright 2026 Fuzz Introspector Authors
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
"""Tests for the second frontend analysis source directory."""
from unittest import mock

from fuzz_introspector.analyses import frontend_analyser


def test_analysis_func_uses_report_basefolder_without_src(
        monkeypatch, tmp_path):
    """Use the report target directory when SRC is not configured."""
    monkeypatch.delenv('SRC', raising=False)
    analyser = frontend_analyser.FrontendAnalyser()
    project = mock.Mock()

    with mock.patch.object(frontend_analyser.utils,
                           'detect_language',
                           return_value='c-cpp') as detect_language, \
         mock.patch.object(frontend_analyser.oss_fuzz,
                           'analyse_folder') as analyse_folder, \
         mock.patch.object(frontend_analyser.analysis,
                           'IntrospectionProject',
                           return_value=project), \
         mock.patch.object(analyser, 'standalone_analysis'):
        analyser.analysis_func(mock.Mock(), [], mock.Mock(), [], str(tmp_path),
                               '', [], str(tmp_path))

    detect_language.assert_called_once_with(str(tmp_path))
    analyse_folder.assert_called_once_with(language='c-cpp',
                                           directory=str(tmp_path),
                                           out=str(tmp_path /
                                                   'second-frontend-run'),
                                           module_only=True)


def test_analysis_func_prefers_src_environment(monkeypatch, tmp_path):
    """Keep using SRC when OSS-Fuzz provides it."""
    source_dir = tmp_path / 'source'
    source_dir.mkdir()
    monkeypatch.setenv('SRC', str(source_dir))
    analyser = frontend_analyser.FrontendAnalyser()
    project = mock.Mock()

    with mock.patch.object(frontend_analyser.utils,
                           'detect_language',
                           return_value='c-cpp') as detect_language, \
         mock.patch.object(frontend_analyser.oss_fuzz,
                           'analyse_folder'), \
         mock.patch.object(frontend_analyser.analysis,
                           'IntrospectionProject',
                           return_value=project), \
         mock.patch.object(analyser, 'standalone_analysis'):
        analyser.analysis_func(mock.Mock(), [], mock.Mock(), [], str(tmp_path),
                               '', [], str(tmp_path))

    detect_language.assert_called_once_with(str(source_dir))

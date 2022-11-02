// Copyright 2022 Fuzz Introspector Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
///////////////////////////////////////////////////////////////////////////

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

import static com.github.javaparser.ParseStart.COMPILATION_UNIT;
import static com.github.javaparser.Providers.provider;
import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ParserConfiguration;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class TestFuzzer {
  public static void fuzzerTestOneInput(FuzzedDataProvider data) {
    String datastring = data.consumeRemainingAsString();
    InputStream datastream = new ByteArrayInputStream(datastring.getBytes());
    try {
        ParserConfiguration configuration = new ParserConfiguration();
        final ParseResult<CompilationUnit> result = new JavaParser(configuration)
        .parse(COMPILATION_UNIT, provider(datastream, configuration.getCharacterEncoding()));
    } catch (Exception e) {
      return;
    }
  }
}

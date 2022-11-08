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

import java.util.Collection;
import java.util.Iterator;

public class TestFuzzer {
  public static void fuzzerTestOneInput(Collection<String> item, Collection<String> item2) {
    item.add("A");
    item.add("B");
    item.add("C");

    item2.addAll(item);

    System.out.println("item size: " + item.size());
    System.out.println("item2 size: " + item2.size());

    Iterator<String> it = item.iterator();
    while (it.hasNext()) {
      System.out.println(it.next());
    }

    if (!item2.equals(item)) {
      item2.clear();
    }
  }
}

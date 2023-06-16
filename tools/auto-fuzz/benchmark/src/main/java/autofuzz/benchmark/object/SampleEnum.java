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

package autofuzz.benchmark.object;

public enum SampleEnum {
    A("Alpha"),
    B("Bravo"),
    C("Charlie"),
    D("Delta"),
    E("Echo"),
    F("Foxtrot"),
    G("Golf"),
    H("Hotel"),
    I("India"),
    J("Jullett");

    public final String label;

    private SampleEnum(String label) {
        this.label = label;
    }

    public static SampleEnum valueOfLabel(String label) {
        for (SampleEnum e : values()) {
            if (e.label.equals(label)) {
                return e;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return this.label;
    }
}

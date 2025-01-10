package simple;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class SimpleClass {
    public SimpleClass() {
        System.out.println("Default Constructor Called");
    }

    public SimpleClass(String param) {
        System.out.println("Constructor with parameter called: " + param.toUpperCase());
    }

    public void simpleMethod() {
        System.out.println("Simple Method Called");
    }

    public void unreachableMethod() {
        System.out.println("Unreachable Method in SimpleClass");
    }
}

public class Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        SimpleClass sc = new SimpleClass(data.consumeString(10));
        sc.simpleMethod();
    }
}

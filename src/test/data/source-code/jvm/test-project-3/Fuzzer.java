package nested;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

class NestedClass {
    static class InnerClass {
        void innerMethod() {
            System.out.println("Inner Method Called");
        }

        void unreachableInnerMethod() {
            System.out.println("Unreachable Method in InnerClass");
        }
    }
}

class RecursiveClass {
    void recursiveMethod(int n) {
        if (n > 0) {
            System.out.println("Recursion depth: " + n);
            recursiveMethod(n - 1);
        }
    }

    void unreachableRecursiveHelper() {
        System.out.println("Unreachable Recursive Helper Method");
    }
}

public class Fuzzer {
    @FuzzTest
    public static void test(FuzzedDataProvider data) {
        NestedClass.InnerClass ic = new NestedClass.InnerClass();
        ic.innerMethod();

        RecursiveClass rc = new RecursiveClass();
        rc.recursiveMethod(3);
    }
}

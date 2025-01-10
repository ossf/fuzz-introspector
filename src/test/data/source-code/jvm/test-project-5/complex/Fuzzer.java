package complex;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

class A {
    B b = new B();

    void callB() {
        b.callC();
    }

    void unreachableAMethod() {
        System.out.println("Unreachable Method in A");
    }
}

class B {
    C c = new C();

    void callC() {
        c.finalMethod();
    }

    void unreachableBMethod() {
        System.out.println("Unreachable Method in B");
    }
}

class C {
    void finalMethod() {
        System.out.println("Final Method in Chain Called");
    }

    void unreachableCMethod() {
        System.out.println("Unreachable Method in C");
    }
}

public class Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        A a = new A();
        a.callB();
    }

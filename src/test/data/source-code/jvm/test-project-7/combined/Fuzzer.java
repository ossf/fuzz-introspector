package combined;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import combined.helper.HelperClass;

abstract class AbstractBase {
    abstract void abstractMethod();

    void unreachableAbstractBaseMethod() {
        System.out.println("Unreachable Method in AbstractBase");
    }
}

class ConcreteClass extends AbstractBase {
    @Override
    void abstractMethod() {
        System.out.println("ConcreteClass Implementation of Abstract Method");
    }

    void chainMethod() {
        System.out.println("Chain Method Called");
        NestedClass.InnerClass ic = new NestedClass.InnerClass();
        ic.innerMethod();
    }

    void unreachableConcreteMethod() {
        System.out.println("Unreachable Method in ConcreteClass");
    }
}

class NestedClass {
    static class InnerClass {
        void innerMethod() {
            System.out.println("Inner Class Method in Combined Project");
        }

        void unreachableInnerClassMethod() {
            System.out.println("Unreachable Method in InnerClass");
        }
    }
}

public class Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        AbstractBase base = new ConcreteClass();
        ((ConcreteClass) base).chainMethod();
        base.abstractMethod();
    }
}

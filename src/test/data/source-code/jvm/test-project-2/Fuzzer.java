package polymorphism;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;

interface Animal {
    void sound();
}

class Dog implements Animal {
    public Dog() {
        System.out.println("Dog Constructor Called: " + Math.random());
    }

    public Dog(String name) {
        System.out.println("Dog Constructor with name: " + name.toLowerCase());
    }

    public void sound() {
        System.out.println("Bark");
    }

    public void unreachableDogMethod() {
        System.out.println("Unreachable Method in Dog");
    }
}

class Cat implements Animal {
    public Cat() {
        System.out.println("Cat Constructor Called: " + Math.random());
    }

    public Cat(String name) {
        System.out.println("Cat Constructor with name: " + name.toUpperCase());
    }

    public void sound() {
        System.out.println("Meow");
    }

    public void unreachableCatMethod() {
        System.out.println("Unreachable Method in Cat");
    }
}

public class Fuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        Animal animal;
        if ("dog".equals(data.consumeString(10))) {
            animal = new Dog(data.consumeString(10));
        } else {
            animal = new Cat(data.consumeString(10));
        }
        animal.sound();
    }
}

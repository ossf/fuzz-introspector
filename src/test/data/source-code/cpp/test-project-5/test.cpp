#include "test.hpp"
#include <iostream>

namespace NamespaceOne {
    void processInput(const std::string& input) {
        std::cout << "NamespaceOne::processInput called with: " << input << std::endl;
    }
}

namespace NamespaceTwo {
    void processInput(const std::string& input) {
        std::cout << "NamespaceTwo::processInput called with: " << input << std::endl;
    }
}

void ClassOne::processInput(const std::string& input) {
    std::cout << "ClassOne::processInput called with: " << input << std::endl;
}

void ClassTwo::processInput(const std::string& input) {
    std::cout << "ClassTwo::processInput called with: " << input << std::endl;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (data == nullptr || size == 0) {
        return 0;
    }
    std::string input(reinterpret_cast<const char*>(data), size);

    NamespaceOne::processInput(input);

    ClassOne obj;
    obj.processInput(input);

    return 0;
}

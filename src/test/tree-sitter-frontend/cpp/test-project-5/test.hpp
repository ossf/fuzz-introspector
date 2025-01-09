// Header File: test.hpp
#ifndef TEST_HPP
#define TEST_HPP

#include <string>

namespace NamespaceOne {
    void processInput(const std::string& input);
}

namespace NamespaceTwo {
    void processInput(const std::string& input);
}

class ClassOne {
public:
    void processInput(const std::string& input);
};

class ClassTwo {
public:
    void processInput(const std::string& input);
};

#endif // TEST_HPP

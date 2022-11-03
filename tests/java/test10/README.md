Testcase demonstrate the effect of polymorphism method.
If the final executed method is depending on the life instance used, then it is impossible to determine which exact method will be called.
Soot list out all possible method call choice for each of those uncertainty which generate a large bunch of repeative line with the same function, same caller line number but different class.
Each of the line is one of the possiblilty that the code will be executed if certain object instance is passed to the code in runtime.


rm -rf ./work
mkdir work
cd work

../../../build/llvm-build/bin/clang -fsanitize=fuzzer -flto -g ../fuzzer.c -o fuzzer

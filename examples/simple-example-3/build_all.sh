rm -rf ./work
mkdir work
cd work

echo "[+] Linking the projects"
../../../build/llvm-build/bin/clang -fsanitize=fuzzer-no-link -g -c -flto ../fuzzer.c -o fuzzer.o
../../../build/llvm-build/bin/clang -fsanitize=fuzzer -g -flto fuzzer.o -o fuzzer

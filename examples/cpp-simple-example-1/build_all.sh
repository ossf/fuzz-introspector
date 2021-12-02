rm -rf ./work
mkdir work
cd work

echo "[+] Linking the projects"
../../../build/llvm-build/bin/clang++ -v -fsanitize=fuzzer-no-link -g -c -flto ../fuzzer.cpp -o fuzzer.o
echo "dos"
../../../build/llvm-build/bin/clang++ -v -fsanitize=fuzzer -g -flto fuzzer.o -o fuzzer
echo "dres"

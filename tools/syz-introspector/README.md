# Automatically analyse linux kernel drivers


## Usage

```
# Set up env
python3.11 -m virtualenv .venv
. .venv/bin/activate

# Clone linux
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git linux

# Clone introspector
git clone https://github.com/ossf/fuzz-introspector
cd fuzz-introspector/src
python3 -m pip install -e .


# Run analysis on a driver in the linux kernel
cd ../../
python3 fuzz-introspector/tools/syz-introspector/src/main.py --kernel-folder=linux --target=linux/drivers/net/ppp
```

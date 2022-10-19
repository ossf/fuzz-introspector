#!/bin/sh

mkdir -p test-jar
rm -rf test-jar/*
for dir in $(ls -d */)
do
cd $dir
./build.sh
cd ..
cp $dir/*.jar test-jar/
done

FROM gcr.io/oss-fuzz-base/base-builder
RUN mkdir tmp
WORKDIR tmp
COPY build.sh $SRC/
COPY temp.c fuzz.h $SRC/tmp/

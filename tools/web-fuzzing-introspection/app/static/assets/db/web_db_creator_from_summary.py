import os
import sys
import json
import requests


def get_all_functions_for_project(project_name, date_str="2023-04-11"):
    try:
        json_raw = requests.get('https://storage.googleapis.com/oss-fuzz-introspector/%s/inspector-report/%s/summary.json'%(project_name, date_str.replace("-","")))
    except:
        return [], None

    #with open('summary.json', 'r') as json_file:
    #    json_dict = json.load(json_file)
    try:
        json_dict = json.loads(json_raw.text)
    except:
        return [], None

    #with open("%s-jj.json"%(project_name), 'w') as f:
    #    json.dump(json_dict, f)

    #print(len(json_dict))
    #for k in json_dict:
    #    #print(k)
    #    if 'MergedProjectProfile' in k:
    #        for k2 in json_dict[k]:
    #            print(k2)

    # Access all functions
    all_function_list = json_dict['MergedProjectProfile']['all-functions']
    project_stats = json_dict['MergedProjectProfile']['stats']
    amount_of_fuzzers = len(json_dict) - 2

    project_timestamp = {
        "project_name": project_name,
        "date": date_str,
        "coverage_lines": project_stats['code-coverage-function-percentage'],
        "static_reachability": project_stats['reached-complexity-percentage'],
        "fuzzer_count": amount_of_fuzzers,
        "function_count": len(all_function_list),
        "introspector_report_url": "",
        "coverage_url": "",
    }

    #print("List of all functions: %d"%(len(all_function_list)))
    #print("Stats:")
    #print(project_stats)
    #print("Number of fuzzers: %d"%(amount_of_functions))
    refined_proj_list = list()
    for func in all_function_list:
        refined_proj_list.append({
            'name': func['Func name'],
            'code_coverage_url': func['func_url'],
            'function_filename': func['Functions filename'],
            'runtime_code_coverage': float(func['Func lines hit %'].replace("%","")),
            'is_reached': len(func['Reached by Fuzzers']) > 1,
            'project': project_name
        })
    return refined_proj_list, project_timestamp


function_list = list()
project_timestamps = list()
project_list = ['htslib', 'libexif', 'hdf5', 'janet', 'opus', 'gpac', 'llhttp', 'postfix', 'c-ares', 'brunsli', 'phpmap', 'lodepng', 'libpng','nettle', 'h2o', 'libxml2', 'libgd', 'zstd', 'flac', 'icu']
project_list = ['lodepng', 'gnupg', 'gpsd', 'ntpsec', 'rapidjson', 'spdlog', 'postgresql', 'openthread', 'jwt-verify-lib', 'zopfli', 'matio', 'libprotobuf-mutator', 'jsoncons', 'ampproject', 'poco', 'espeak-ng', 'libssh2', 'brotli', 'dng_sdk', 'json', 'pugixml', 'cryptsetup', 'zlib-ng', 's2geometry', 'xerces-c', 'bzip2', 'ecc-diff-fuzzer', 'trafficserver', 'libressl', 'libsndfile', 'thrift', 'libpng', 'ibmswtpm2', 'yara', 'dbus-broker', 'fuzzing-puzzles', 'sql-parser', 'brpc', 'jsoncpp', 'brunsli', 'cctz', 'pffft', 'simd', 'cura-engine', 'wget2', 'resiprocate', 'apache-httpd', 'libxml2', 'glib', 'libarchive', 'fwupd', 'muduo', 'gdk-pixbuf', 'avahi', 'immer', 'croaring', 'poppler', 'samba', 'bind9', 'wuffs', 'harfbuzz', 'openweave', 'geos', 'vulnerable-project', 'sqlite3', 'libmpeg2', 'h3', 'rdkit', 'pidgin', 'lz4', 'spotify-json', 'liblouis', 'gdbm', 'miniz', 'nodejs', 'freetype2', 'ghostscript', 'wabt', 'lame', 'qubes-os', 'http-parser', 'envoy', 'zstd', 'grpc-httpjson-transcoding', 'num-bigint', 'xs', 'fribidi', 'cgif', 'myanmar-tools', 'cairo', 'nanopb', 'civetweb', 'xbps', 'fast_float', 'circl', 'valijson', 'librdkafka', 'cups', 'librawspeed', 'hunspell', 'opendnp3', 'aspell', 'postfix', 'libcbor', 'libvnc', 'wpantund', 'xnu', 'libpsl', 'skia-ftz', 'pupnp', 'capstone', 'powerdns', 'libsrtp', 'libavif', 'mpg123', 'python3-libraries', 'wxwidgets', 'elfutils', 'bazel-rules-fuzzing-test', 'grok', 'sentencepiece', 'libphonenumber', 'php', 'libsodium', 'qemu', 'radare2', 'pcl', 'bloaty', 'zydis', 'freeradius', 'libaom', 'msquic', 'libplist', 'njs', 'mupdf', 'orbit', 'libwebsockets', 'mbedtls', 'libdwarf', 'lighttpd', 'boringssl', 'json-c', 'dropbear', 'dav1d', 'exprtk', 'varnish', 'bluez', 'fio', 'ruby', 'llvm_libcxxabi', 'perfetto', 'rocksdb', 'unbound', 'easywsclient', 'tink', 'libraw', 'rtpproxy', 'libavc', 'augeas', 'bls-signatures', 'ffmpeg', 'git', 'snappy', 'hoextdown', 'libtasn1', 'llvm_libcxx', 'picotls', 'libcacard', 'exiv2', 'frr', 'libyaml', 'tesseract-ocr', 'pjsip', 'nss', 'clickhouse', 'usbguard', 'libspectre', 'wireshark', 'libiec61850', 'monero', 'systemd', 'mosquitto', 'bitcoin-core', 'libpcap', 'mosh', 'postgis', 'boost-json', 'fast-dds', 'rnp', 'libtheora', 'nginx', 'botan', 'hdf5', 'libidn', 'cxxopts', 'bad_example', 'libigl', 'msgpack-c', 'libreoffice', 'tint', 'irssi', 'graphicsfuzz-spirv', 'http-pattern-matcher', 'simdutf', 'c-ares', 'utf8proc', 'protobuf-c', 'libucl', 'clib', 'piex', 'libpng-proto', 'gdal', 'muparser', 'opencv', 'p11-kit', 'lxc', 'skcms', 'openssh', 'pigweed', 'usrsctp', 'libecc', 'libxls', 'hiredis', 'libass', 'libldac', 'openexr', 'spicy', 'wavpack', 'flac', 'double-conversion', 'iroha', 'cel-cpp', 'pycryptodome', 'net-snmp', 'openvswitch', 'file', 'leveldb', 'tmux', 'wasm3', 'zeek', 'unit', 'openbabel', 'libical', 'libyuv', 'wget', 'mruby', 'cmake', 'nghttp2', 'cmark', 'libzmq', 'wolfmqtt', 'opensips', 'libzip', 'numactl', 'neomutt', 'opus', 'sleuthkit', 'libbpf', 'xvid', 'libgd', 'ostree', 'kcodecs', 'libpg_query', 'coturn', 'capnproto', 'lzma', 'fluent-bit', 'pcapplusplus', 'e2fsprogs', 'grpc', 'woff2', 'sound-open-firmware', 'libusb', 'libvpx', 'giflib', 'arduinojson', 'binutils', 'curl', 'libteken', 'tinyobjloader', 'meshoptimizer', 'tor', 'janet', 'selinux', 'readstat', 'nestegg', 'ntp', 'libxslt', 'kamailio', 'lwan', 'firefox', 'c-blosc2', 'dnsmasq', 'opensc', 'libgit2', 'dart', 'llhttp', 'libmodbus', 'ndpi', 'dlplibs', 'libevent', 're2', 'libssh', 'fuzztest-raksha', 'mongoose', 'lua', 'bignum-fuzzer', 'draco', 'uwebsockets', 'guetzli', 'netcdf', 'libhevc', 'flatbuffers', 'vlc', 'proj4', 'fuzztest-example', 'simdjson', 'libjxl', 'libspng', 'lldpd', 'c-blosc', 'glog', 'tinyxml2', 'vorbis', 'jsc', 'bearssl', 'mercurial', 'uriparser', 'h2o', 'spdk', 'libtpms', 'example', 'eigen', 'lcms', 'tdengine', 'znc', 'llvm', 'tensorflow', 'minizip', 'janus-gateway', 'kimageformats', 'wazuh', 'tarantool', 'gstreamer', 'libtsm', 'htslib', 'cryptofuzz', 'w3m', 'xz', 'igraph', 'spidermonkey', 'cifuzz-example', 'hostap', 'karchive', 'haproxy', 'openh264', 'krb5', 'tinyusb', 'strongswan', 'tcmalloc', 'rustcrypto', 'leptonica', 'cpython3', 'proftpd', 'md4c', 'util-linux', 'unicorn', 'spirv-tools', 'arrow', 'firestore', 'xpdf', 'opendds', 'yajl-ruby', 'openssl', 'libyang', 'libtiff', 'pngquant', 'opusfile', 's2opc', 'pcre2', 'alembic', 'gfwx', 'libheif', 'oatpp', 'freeimage', 'proxygen', 'jansson', 'relic', 'quickjs', 'inchi', 'cras', 'xmlsec', 'osquery', 'clamav', 'sudoers', 'openjpeg', 'libredwg', 'boost', 'stb', 'cfengine', 'libwebp', 'mysql-server', 'spidermonkey-ufi', 'tidy-html5', 'libidn2', 'lzo', 'solidity', 'astc-encoder', 'mapserver', 'esp-v2', 'jbig2dec', 'hermes', 'rabbitmq-c', 'keystone', 'qpdf', 'imagemagick', 'tremor', 'oniguruma', 'opencensus-cpp', 'serenity', 'ots', 'phmap', 'dovecot', 'cppcheck', 'icu', 'casync', 'duckdb', 'libcoap', 'libexif', 'nettle', 'tinygltf', 'cjson', 'gnutls', 'libyal', 'jsonnet', 'libfdk-aac', 'libtorrent', 'gpac', 'skia', 'fmt', 'wolfssl', 'mdbtools', 'graphicsmagick', 'libvips', 'libsass', 'pistache', 'expat', 'libjpeg-turbo', 'cyclonedds', 'open62541', 'tpm2-tss', 'openvpn', 'cpp-httplib', 'zlib', 'unrar', 'qpid-proton', 'spice-usbredir', 'speex', 'libfido2', 'ninja', 'assimp', 'qt', 'tpm2', 'knot-dns', 'lldb-eval', 'abseil-cpp']

accummulated_fuzzer_count = 0
accummulated_function_count = 0
for project_name in project_list:
    print("%d"%(len(function_list)))
    project_function_list, project_timestamp = get_all_functions_for_project(project_name)
    if project_timestamp is None:
        continue
    function_list += project_function_list
    project_timestamps.append(project_timestamp)

    accummulated_fuzzer_count += project_timestamp['fuzzer_count']
    accummulated_function_count += project_timestamp['function_count']


# Create a DB timestamp
db_timestamp = {
    "date": "2023-01-15",
    "project_count": len(project_timestamps),
    "fuzzer_count": accummulated_fuzzer_count,
    "function_count": accummulated_function_count,
}


with open('all-functions-db.json', 'w') as f:
    json.dump(function_list, f)
with open('all-project-timestamps.json', 'w') as f:
    json.dump(project_timestamps, f)
with open('db-timestamps.json', 'w') as f:
    json.dump([db_timestamp], f)

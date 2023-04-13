import os
import sys
import json
import datetime
import requests

DB_JSON_DB_TIMESTAMP = 'db-timestamps.json'
DB_JSON_ALL_PROJECT_TIMESTAMP = 'all-project-timestamps.json'
DB_JSON_ALL_FUNCTIONS = 'all-functions-db.json'
DB_JSON_ALL_CURRENT_FUNCS = 'all-project-current.json'

ALL_JSON_FILES = [
    DB_JSON_DB_TIMESTAMP,
    DB_JSON_ALL_PROJECT_TIMESTAMP,
    DB_JSON_ALL_FUNCTIONS,
    DB_JSON_ALL_CURRENT_FUNCS,
]

def get_introspector_report_url_base(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-introspector/{0}/inspector-report/{1}/'
    project_url = base_url.format(project_name, datestr)
    return project_url

def get_introspector_report_url_summary(project_name, datestr):
    return get_introspector_report_url_base(project_name, datestr) + "summary.json"

def get_introspector_report_url_report(project_name, datestr):
    return get_introspector_report_url_base(project_name, datestr) + "fuzz_report.html"

def get_coverage_report_url(project_name, datestr):
    base_url = 'https://storage.googleapis.com/oss-fuzz-coverage/{0}/reports/{1}/linux/report.html'
    project_url = base_url.format(project_name, datestr)
    return project_url

def get_all_functions_for_project(project_name, date_str="2023-04-11"):
    
    introspector_summary_url = get_introspector_report_url_summary(project_name, date_str.replace("-",""))
    introspector_report_url = get_introspector_report_url_report(project_name, date_str.replace("-",""))
    coverage_url = get_coverage_report_url(project_name, date_str.replace("-",""))
    try:
        json_raw = requests.get(introspector_summary_url)
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
        "introspector_report_url": introspector_report_url,
        "coverage_url": coverage_url,
    }

    #print("List of all functions: %d"%(len(all_function_list)))
    #print("Stats:")
    #print(project_stats)
    #print("Number of fuzzers: %d"%(amount_of_functions))
    has_c = False
    has_cpp = False
    has_py = False
    has_java = False
    refined_proj_list = list()
    for func in all_function_list:
        if func['Functions filename'].endswith(".c"):
            has_c = True
        if func['Functions filename'].endswith(".cc"):
            has_cpp = True
        if func['Functions filename'].endswith(".cpp"):
            has_cpp = True
        if func['Functions filename'].endswith(".py"):
            has_py = True
        if func['Functions filename'].endswith(".java"):
            has_java = True

        refined_proj_list.append({
            'name': func['Func name'],
            'code_coverage_url': func['func_url'],
            'function_filename': func['Functions filename'],
            'runtime_code_coverage': float(func['Func lines hit %'].replace("%","")),
            'is_reached': len(func['Reached by Fuzzers']) > 1,
            'project': project_name
        })
    if has_c:
        project_timestamp['language'] = 'c'
    if has_cpp:
        project_timestamp['language'] = 'c++'
    if has_py:
        project_timestamp['language'] = 'python'
    if has_java:
        project_timestamp['language'] = 'java'

    return refined_proj_list, project_timestamp

def analyse_list_of_projects(date, projects_to_analyse):
    """Creates a DB snapshot of a list of projects for a given date."""
    function_list = list()
    project_timestamps = list()
    accummulated_fuzzer_count = 0
    accummulated_function_count = 0
    for project_name in projects_to_analyse:
        print("%d"%(len(function_list)))
        project_function_list, project_timestamp = get_all_functions_for_project(project_name, date)
        if project_timestamp is None:
            continue
        function_list += project_function_list
        project_timestamps.append(project_timestamp)

        accummulated_fuzzer_count += project_timestamp['fuzzer_count']
        accummulated_function_count += project_timestamp['function_count']

    # Create a DB timestamp
    db_timestamp = {
        "date": date,
        "project_count": len(project_timestamps),
        "fuzzer_count": accummulated_fuzzer_count,
        "function_count": accummulated_function_count,
    }
    return function_list, project_timestamps, db_timestamp

#def extend_project_project_timestamps(project_timestamps):
#    if os.path.isfile('

def extend_db_timestamps(db_timestamp):
    existing_timestamps = []
    if os.path.isfile(DB_JSON_DB_TIMESTAMP):
        with open(DB_JSON_DB_TIMESTAMP, 'r') as f:
            try:
                existing_timestamps = json.load(f)
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []
    to_add = True
    for ts in existing_timestamps:
        if ts['date'] == db_timestamp['date']:
            to_add = False
    if to_add:
        existing_timestamps.append(db_timestamp)
        with open(DB_JSON_DB_TIMESTAMP, 'w') as f:
            json.dump(existing_timestamps, f)
    

def extend_project_timestamps(project_timestamps):
    existing_timestamps = []
    if os.path.isfile(DB_JSON_ALL_PROJECT_TIMESTAMP):
        with open(DB_JSON_ALL_PROJECT_TIMESTAMP, 'r') as f:
            try:
                existing_timestamps = json.load(f)
            except:
                existing_timestamps = []
    else:
        existing_timestamps = []

    have_added = False
    for new_ts in project_timestamps:
        to_add = True
        for ts in existing_timestamps:
            if ts['date'] == new_ts['date'] and ts['project_name'] == new_ts['project_name']:
                to_add = False
        if to_add:
            existing_timestamps.append(new_ts)
            have_added = True
    if have_added:
        with open(DB_JSON_ALL_PROJECT_TIMESTAMP, 'w') as f:
            json.dump(existing_timestamps, f)

    with open(DB_JSON_ALL_CURRENT_FUNCS, 'w') as f:
        json.dump(project_timestamps, f)

    

project_list = ['lodepng', 'gnupg', 'gpsd', 'ntpsec', 'rapidjson', 'spdlog', 'postgresql', 'openthread', 'jwt-verify-lib', 'zopfli', 'matio', 'libprotobuf-mutator', 'jsoncons', 'ampproject', 'poco', 'espeak-ng', 'libssh2', 'brotli', 'dng_sdk', 'json', 'pugixml', 'cryptsetup', 'zlib-ng', 's2geometry', 'xerces-c', 'bzip2', 'ecc-diff-fuzzer', 'trafficserver', 'libressl', 'libsndfile', 'thrift', 'libpng', 'ibmswtpm2', 'yara', 'dbus-broker', 'fuzzing-puzzles', 'sql-parser', 'brpc', 'jsoncpp', 'brunsli', 'cctz', 'pffft', 'simd', 'cura-engine', 'wget2', 'resiprocate', 'apache-httpd', 'libxml2', 'glib', 'libarchive', 'fwupd', 'muduo', 'gdk-pixbuf', 'avahi', 'immer', 'croaring', 'poppler', 'samba', 'bind9', 'wuffs', 'harfbuzz', 'openweave', 'geos', 'vulnerable-project', 'sqlite3', 'libmpeg2', 'h3', 'rdkit', 'pidgin', 'lz4', 'spotify-json', 'liblouis', 'gdbm', 'miniz', 'nodejs', 'freetype2', 'ghostscript', 'wabt', 'lame', 'qubes-os', 'http-parser', 'envoy', 'zstd', 'grpc-httpjson-transcoding', 'num-bigint', 'xs', 'fribidi', 'cgif', 'myanmar-tools', 'cairo', 'nanopb', 'civetweb', 'xbps', 'fast_float', 'circl', 'valijson', 'librdkafka', 'cups', 'librawspeed', 'hunspell', 'opendnp3', 'aspell', 'postfix', 'libcbor', 'libvnc', 'wpantund', 'xnu', 'libpsl', 'skia-ftz', 'pupnp', 'capstone', 'powerdns', 'libsrtp', 'libavif', 'mpg123', 'python3-libraries', 'wxwidgets', 'elfutils', 'bazel-rules-fuzzing-test', 'grok', 'sentencepiece', 'libphonenumber', 'php', 'libsodium', 'qemu', 'radare2', 'pcl', 'bloaty', 'zydis', 'freeradius', 'libaom', 'msquic', 'libplist', 'njs', 'mupdf', 'orbit', 'libwebsockets', 'mbedtls', 'libdwarf', 'lighttpd', 'boringssl', 'json-c', 'dropbear', 'dav1d', 'exprtk', 'varnish', 'bluez', 'fio', 'ruby', 'llvm_libcxxabi', 'perfetto', 'rocksdb', 'unbound', 'easywsclient', 'tink', 'libraw', 'rtpproxy', 'libavc', 'augeas', 'bls-signatures', 'ffmpeg', 'git', 'snappy', 'hoextdown', 'libtasn1', 'llvm_libcxx', 'picotls', 'libcacard', 'exiv2', 'frr', 'libyaml', 'tesseract-ocr', 'pjsip', 'nss', 'clickhouse', 'usbguard', 'libspectre', 'wireshark', 'libiec61850', 'monero', 'systemd', 'mosquitto', 'bitcoin-core', 'libpcap', 'mosh', 'postgis', 'boost-json', 'fast-dds', 'rnp', 'libtheora', 'nginx', 'botan', 'hdf5', 'libidn', 'cxxopts', 'bad_example', 'libigl', 'msgpack-c', 'libreoffice', 'tint', 'irssi', 'graphicsfuzz-spirv', 'http-pattern-matcher', 'simdutf', 'c-ares', 'utf8proc', 'protobuf-c', 'libucl', 'clib', 'piex', 'libpng-proto', 'gdal', 'muparser', 'opencv', 'p11-kit', 'lxc', 'skcms', 'openssh', 'pigweed', 'usrsctp', 'libecc', 'libxls', 'hiredis', 'libass', 'libldac', 'openexr', 'spicy', 'wavpack', 'flac', 'double-conversion', 'iroha', 'cel-cpp', 'pycryptodome', 'net-snmp', 'openvswitch', 'file', 'leveldb', 'tmux', 'wasm3', 'zeek', 'unit', 'openbabel', 'libical', 'libyuv', 'wget', 'mruby', 'cmake', 'nghttp2', 'cmark', 'libzmq', 'wolfmqtt', 'opensips', 'libzip', 'numactl', 'neomutt', 'opus', 'sleuthkit', 'libbpf', 'xvid', 'libgd', 'ostree', 'kcodecs', 'libpg_query', 'coturn', 'capnproto', 'lzma', 'fluent-bit', 'pcapplusplus', 'e2fsprogs', 'grpc', 'woff2', 'sound-open-firmware', 'libusb', 'libvpx', 'giflib', 'arduinojson', 'binutils', 'curl', 'libteken', 'tinyobjloader', 'meshoptimizer', 'tor', 'janet', 'selinux', 'readstat', 'nestegg', 'ntp', 'libxslt', 'kamailio', 'lwan', 'firefox', 'c-blosc2', 'dnsmasq', 'opensc', 'libgit2', 'dart', 'llhttp', 'libmodbus', 'ndpi', 'dlplibs', 'libevent', 're2', 'libssh', 'fuzztest-raksha', 'mongoose', 'lua', 'bignum-fuzzer', 'draco', 'uwebsockets', 'guetzli', 'netcdf', 'libhevc', 'flatbuffers', 'vlc', 'proj4', 'fuzztest-example', 'simdjson', 'libjxl', 'libspng', 'lldpd', 'c-blosc', 'glog', 'tinyxml2', 'vorbis', 'jsc', 'bearssl', 'mercurial', 'uriparser', 'h2o', 'spdk', 'libtpms', 'example', 'eigen', 'lcms', 'tdengine', 'znc', 'llvm', 'tensorflow', 'minizip', 'janus-gateway', 'kimageformats', 'wazuh', 'tarantool', 'gstreamer', 'libtsm', 'htslib', 'cryptofuzz', 'w3m', 'xz', 'igraph', 'spidermonkey', 'cifuzz-example', 'hostap', 'karchive', 'haproxy', 'openh264', 'krb5', 'tinyusb', 'strongswan', 'tcmalloc', 'rustcrypto', 'leptonica', 'cpython3', 'proftpd', 'md4c', 'util-linux', 'unicorn', 'spirv-tools', 'arrow', 'firestore', 'xpdf', 'opendds', 'yajl-ruby', 'openssl', 'libyang', 'libtiff', 'pngquant', 'opusfile', 's2opc', 'pcre2', 'alembic', 'gfwx', 'libheif', 'oatpp', 'freeimage', 'proxygen', 'jansson', 'relic', 'quickjs', 'inchi', 'cras', 'xmlsec', 'osquery', 'clamav', 'sudoers', 'openjpeg', 'libredwg', 'boost', 'stb', 'cfengine', 'libwebp', 'mysql-server', 'spidermonkey-ufi', 'tidy-html5', 'libidn2', 'lzo', 'solidity', 'astc-encoder', 'mapserver', 'esp-v2', 'jbig2dec', 'hermes', 'rabbitmq-c', 'keystone', 'qpdf', 'imagemagick', 'tremor', 'oniguruma', 'opencensus-cpp', 'serenity', 'ots', 'phmap', 'dovecot', 'cppcheck', 'icu', 'casync', 'duckdb', 'libcoap', 'libexif', 'nettle', 'tinygltf', 'cjson', 'gnutls', 'libyal', 'jsonnet', 'libfdk-aac', 'libtorrent', 'gpac', 'skia', 'fmt', 'wolfssl', 'mdbtools', 'graphicsmagick', 'libvips', 'libsass', 'pistache', 'expat', 'libjpeg-turbo', 'cyclonedds', 'open62541', 'tpm2-tss', 'openvpn', 'cpp-httplib', 'zlib', 'unrar', 'qpid-proton', 'spice-usbredir', 'speex', 'libfido2', 'ninja', 'assimp', 'qt', 'tpm2', 'knot-dns', 'lldb-eval', 'abseil-cpp']
#project_list = ['htslib', 'libexif', 'hdf5', 'janet', 'opus', 'gpac', 'llhttp', 'postfix', 'c-ares', 'brunsli', 'phpmap']


def analyse_set_of_dates(dates, projects_to_analyse):
    dates_to_analyse = len(dates)
    idx = 0
    for date in dates:
        print("Analysing date %s -- [%d of %d]"%(date, idx, dates_to_analyse))
        idx += 1
        function_list, project_timestamps, db_timestamp = analyse_list_of_projects(date, projects_to_analyse)
        with open(DB_JSON_ALL_FUNCTIONS, 'w') as f:
            json.dump(function_list, f)
        #with open('all-project-timestamps.json', 'w') as f:
        #    json.dump(project_timestamps, f)
        extend_project_timestamps(project_timestamps)
        extend_db_timestamps(db_timestamp)
        #with open('db-timestamps.json', 'w') as f:
        #    json.dump([db_timestamp], f)

def get_date_at_offset_as_str(day_offset=-1):
    datestr = (datetime.date.today() +
               datetime.timedelta(day_offset)).strftime("%Y-%m-%d")
    return datestr

def cleanup():
    for f in ALL_JSON_FILES:
        if os.path.isfile(f):
            os.remove(f)

cleanup()
dates_list = []
for i in list(reversed(list(range(2,24)))):
    dates_list.append(get_date_at_offset_as_str(i * -1))

analyse_set_of_dates(dates_list, project_list[0:100])

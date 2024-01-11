# Copyright 2024 Fuzz Introspector Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any, Dict

SINK_FUNCTION: Dict[str, Dict[str, Dict[str, Any]]] = {
    'CWE78': {
        'metadata': {
            'id': 78,
            'description': 'Command Injection'
        },
        'sink': {
            'c-cpp': [('', 'system'), ('', 'execl'), ('', 'execlp'),
                      ('', 'execle'), ('', 'execv'), ('', 'execvp'),
                      ('', 'execve'), ('', 'wordexp'), ('', 'popen')],
            'python': [('<builtin>', 'exec'), ('<builtin>', 'eval'),
                       ('subprocess', 'call'), ('subprocess', 'run'),
                       ('subprocess', 'Popen'), ('subprocess', 'check_output'),
                       ('os', 'system'), ('os', 'popen'), ('os', 'spawn'),
                       ('os', 'spawnl'), ('os', 'spawnle'), ('os', 'spawnlp'),
                       ('os', 'spawnlpe'), ('os', 'spawnv'), ('os', 'spawnvp'),
                       ('os', 'spawnve'), ('os', 'spawnvpe'), ('os', 'exec'),
                       ('os', 'execl'), ('os', 'execle'), ('os', 'execlp'),
                       ('os', 'execlpe'), ('os', 'execv'), ('os', 'execve'),
                       ('os', 'execvp'), ('os', 'execlpe'),
                       ('asyncio', 'create_subprocess_shell'),
                       ('asyncio', 'create_subprocess_exec'),
                       ('code.InteractiveInterpreter', 'runsource'),
                       ('code.InteractiveInterpreter', 'runcode'),
                       ('code.InteractiveInterpreter', 'write'),
                       ('code.InteractiveConsole', 'push'),
                       ('code.InteractiveConsole', 'interact'),
                       ('code.InteractiveConsole', 'raw_input'),
                       ('code', 'interact'), ('code', 'compile_command')],
            'jvm': [('java.lang.Runtime', 'exec'),
                    ('javax.xml.xpath.XPath', 'compile'),
                    ('javax.xml.xpath.XPath', 'evaluate'),
                    ('java.util.concurrent.Executor', 'execute'),
                    ('java.util.concurrent.Callable', 'call'),
                    ('java.lang.System', 'console'),
                    ('java.lang.System', 'load'),
                    ('java.lang.System', 'loadLibrary'),
                    ('java.lang.System', 'mapLibraryName'),
                    ('java.lang.System', 'runFinalization'),
                    ('java.lang.System', 'exec'),
                    ('java.lang.ProcessBuilder', 'directory'),
                    ('java.lang.ProcessBuilder', 'inheritIO'),
                    ('java.lang.ProcessBuilder', 'command'),
                    ('java.lang.ProcessBuilder', 'redirectError'),
                    ('java.lang.ProcessBuilder', 'redirectErrorStream'),
                    ('java.lang.ProcessBuilder', 'redirectInput'),
                    ('java.lang.ProcessBuilder', 'redirectOutput'),
                    ('java.lang.ProcessBuilder', 'start')]
        }
    },
    'CWE79': {
        'metadata': {
            'id': 79,
            'description': 'Cross-site Scripting'
        },
        'sink': {
            'c-cpp': [('', 'put'), ('', 'puts'), ('', 'getenv'), ('', 'putc'),
                      ('', 'fputc'), ('', 'putchar')],
            'python': [('jinja2.Environment', 'get_template'),
                       ('jinja2.Environment', 'from_string'),
                       ('jinja2.Template', 'render'),
                       ('jinja2.Template', 'stream'),
                       ('flask', 'make_response')],
            'jvm': [('java.io.PrintWriter', 'print'),
                    ('java.io.PrintWriter', 'printf'),
                    ('java.io.PrintWriter', 'println'),
                    ('java.io.PrintWriter', 'write'),
                    ('java.io.OutputStream', 'write')]
        }
    },
    'CWE787': {
        'metadata': {
            'id': 787,
            'description': 'Out-of-bounds Write (Buffer overflow)'
        },
        'sink': {
            'c-cpp':
            [('', 'malloc'), ('', 'alligned_alloc'), ('', 'xmalloc'),
             ('', 'calloc'), ('', 'realloc'), ('', 'strcpy'), ('', 'strcpy_s'),
             ('', 'strncpy'), ('', 'strncpy_s'), ('', 'strcat'),
             ('', 'strcat_s'), ('', 'strncat'), ('', 'strncat_s'),
             ('', 'strxfrm'), ('', 'strdup'), ('', 'strndup'), ('', 'memchr'),
             ('', 'memset'), ('', 'memset_explicit'), ('', 'memset_s'),
             ('', 'memcpy'), ('', 'memcpy_s'), ('', 'memmove'),
             ('', 'memmove_s'), ('', 'memccpy'), ('', 'putc'), ('', 'fputc'),
             ('', 'putchar'), ('', 'puts'), ('', 'put'), ('', 'fwrite'),
             ('', 'ungetc'), ('', 'fputwc'), ('', 'putwc'), ('', 'fputws'),
             ('', 'putwchar'), ('', 'ungetwc')],
            'python': [],
            'jvm': []
        }
    },
    'CWE89': {
        'metadata': {
            'id': 89,
            'description': 'SQL Injection'
        },
        'sink': {
            'c-cpp': [('', 'runSql'), ('', 'runQuery')],
            'python': [('cursor.MySQLCursor', 'execute'),
                       ('cursor.MySQLCursor', 'executemany'),
                       ('cursor.MySQLCursor', 'executescript'),
                       ('psycopg2.extensions.cursor', 'execute'),
                       ('psycopg2.extensions.cursor', 'executemany'),
                       ('psycopg2.extensions.cursor', 'executescript'),
                       ('sqlite3.Cursor', 'execute'),
                       ('sqlite3.Cursor', 'executemany'),
                       ('sqlite3.Cursor', 'executescript'),
                       ('sqlite3.dbapi2.Cursor', 'execute'),
                       ('sqlite3.dbapi2.Cursor', 'executemany'),
                       ('sqlite3.dbapi2.Cursor', 'executescript')],
            'jvm':
            [('java.sql.Statement', 'execute'),
             ('java.sql.Statement', 'executeBatch'),
             ('java.sql.Statement', 'executeLargeBatch'),
             ('java.sql.Statement', 'executeLargeUpdate'),
             ('java.sql.Statement', 'executeQuery'),
             ('java.sql.Statement', 'executeUpdate'),
             ('java.sql.Statement', 'addBatch'),
             ('javax.persistence.EntityManager', 'createNativeQuery'),
             ('javax.persistence.EntityManager', 'createQuery'),
             ('javax.persistence.EntityManager', 'createStoredProcedureQuery')]
        }
    },
    'CWE416': {
        'metadata': {
            'id': 416,
            'description': 'Use After Free'
        },
        'sink': {
            'c-cpp': [('', 'c_str'), ('', 'getUniquePointer'), ('', 'free'),
                      ('', 'get')],
            'python': [],
            'jvm': []
        }
    },
    'CWE20': {
        'metadata': {
            'id': 20,
            'description': 'Improper Input Validation'
        },
        'sink': {
            'c-cpp': [('', 'fread'), ('', 'fgetc'), ('', 'getc'),
                      ('', 'fgets'), ('', 'getchar'), ('', 'gets'),
                      ('', 'gets_s'), ('', 'get'), ('', 'fget'),
                      ('', 'fgetwc'), ('', 'getwc'), ('', 'fgetws'),
                      ('', 'getwchar'), ('', 'scanf'), ('', 'fscanf'),
                      ('', 'sscanf'), ('', 'scanf_s'), ('', 'fscanf_s'),
                      ('', 'sscanf_s'), ('', 'vscanf'), ('', 'vfscanf'),
                      ('', 'vsscanf'), ('', 'vscanf_s'), ('', 'vfscanf_s'),
                      ('', 'vsscanf_s'), ('', 'wscanf'), ('', 'fwscanf'),
                      ('', 'swscanf'), ('', 'wscanf_s'), ('', 'fwscanf_s'),
                      ('', 'swscanf_s'), ('', 'vwscanf'), ('', 'vfwscanf'),
                      ('', 'vswscanf'), ('', 'vwscanf_s'), ('', 'vfwscanf_s'),
                      ('', 'vswscanf_s')],
            'python':
            [('re', 'compile'), ('re.Pattern', 'match'),
             ('flask.Request', 'get_data'), ('flask.Request', 'get_json'),
             ('flask.Request', 'args'), ('flask.Request', 'charset'),
             ('flask.Request', 'content_encoding'),
             ('flask.Request', 'content_length'),
             ('flask.Request', 'content_md5'),
             ('flask.Request', 'content_type'), ('flask.Request', 'cookies'),
             ('flask.Request', 'files'), ('flask.Request', 'headers')],
            'jvm':
            [('javax.servlet.http.HttpServletRequest', 'getAttribute'),
             ('javax.servlet.http.HttpServletRequest', 'getAttributeNames'),
             ('javax.servlet.http.HttpServletRequest', 'getAuthType'),
             ('javax.servlet.http.HttpServletRequest', 'getCharacterEncoding'),
             ('javax.servlet.http.HttpServletRequest', 'getContentType'),
             ('javax.servlet.http.HttpServletRequest', 'getContextPath'),
             ('javax.servlet.http.HttpServletRequest', 'getCookies'),
             ('javax.servlet.http.HttpServletRequest', 'getDateHeader'),
             ('javax.servlet.http.HttpServletRequest', 'getHeader'),
             ('javax.servlet.http.HttpServletRequest', 'getHeaderNames'),
             ('javax.servlet.http.HttpServletRequest', 'getIntHeader'),
             ('javax.servlet.http.HttpServletRequest', 'getMethod'),
             ('javax.servlet.http.HttpServletRequest', 'getParameter'),
             ('javax.servlet.http.HttpServletRequest', 'getParameterMap'),
             ('javax.servlet.http.HttpServletRequest', 'getParameterNames'),
             ('javax.servlet.http.HttpServletRequest', 'getParameterValues'),
             ('javax.servlet.http.HttpServletRequest', 'getPart'),
             ('javax.servlet.http.HttpServletRequest', 'getParts'),
             ('javax.servlet.http.HttpServletRequest', 'getPathInfo'),
             ('javax.servlet.http.HttpServletRequest', 'getPathTranslated'),
             ('javax.servlet.http.HttpServletRequest', 'getQueryString'),
             ('javax.servlet.http.HttpServletRequest', 'getRemoteUser'),
             ('javax.servlet.http.HttpServletRequest',
              'getRequestedSessionId'),
             ('javax.servlet.http.HttpServletRequest', 'getRequestURI'),
             ('javax.servlet.http.HttpServletRequest', 'getRequestURL'),
             ('java.io.InputStream', 'read'),
             ('java.io.BufferedReader', 'read'),
             ('java.io.BufferedReader', 'readLine'),
             ('java.lang.System', 'getenv'),
             ('java.lang.System', 'getProperties'),
             ('java.lang.System', 'getProperty'), ('java.lang.System', 'load'),
             ('java.lang.System', 'loadLibrary'),
             ('java.lang.System', 'getSecurityManager')]
        }
    },
    'CWE22': {
        'metadata': {
            'id': 22,
            'description': 'Path Traversal'
        },
        'sink': {
            'c-cpp': [('', 'open'), ('', 'write'), ('', 'ostrm'), ('', 'copy'),
                      ('', 'copy_file'), ('', 'copy_symlink'),
                      ('', 'absolute'), ('', 'canonical'), ('', 'relative'),
                      ('', 'create_directory'), ('', 'create_directories'),
                      ('', 'creatE_hard_link'), ('', 'create_symlink'),
                      ('', 'create_directory_symlink'), ('', 'remove'),
                      ('', 'remove_all'), ('', 'rename'), ('', 'resize_file'),
                      ('', 'opendir'), ('', 'readdir'), ('', 'readdir_r'),
                      ('', 'fopen')],
            'python': [('tarfile', 'open'), ('zipfile', 'open'),
                       ('<builtin>', 'open'), ('os.path', 'join')],
            'jvm':
            [('java.io.InputStream', '<init>'), ('java.io.File', '<init>'),
             ('java.io.BufferedReader', '<init>'),
             ('java.nio.file.Paths', 'get'),
             ('java.nio.file.Files', 'createDirectories'),
             ('java.nio.file.Files', 'createDirectory'),
             ('java.nio.file.Files', 'createFile'),
             ('java.nio.file.Files', 'createLink'),
             ('java.nio.file.Files', 'createSymbolicLink'),
             ('java.nio.file.Files', 'createTempDirectory'),
             ('java.nio.file.Files', 'createTempFile'),
             ('java.nio.file.Files', 'delete'),
             ('java.nio.file.Files', 'deleteIfExists'),
             ('java.nio.file.Files', 'find'), ('java.nio.file.Files', 'move'),
             ('java.nio.file.Files', 'write'),
             ('java.io.File', 'createNewFile'),
             ('java.io.File', 'createTempFile'), ('java.io.File', 'delete'),
             ('java.io.File', 'deleteOnExit'), ('java.io.File', 'delete'),
             ('java.io.File', 'renameTo'),
             ('org.apache.commons.io.FileUtils', 'cleanDirectory'),
             ('org.apache.commons.io.FileUtils', 'copyDirectory'),
             ('org.apache.commons.io.FileUtils', 'copyFile'),
             ('org.apache.commons.io.FileUtils', 'copyFileToDirectory'),
             ('org.apache.commons.io.FileUtils', 'copyInputStreamToFile'),
             ('org.apache.commons.io.FileUtils', 'copyToDirectory'),
             ('org.apache.commons.io.FileUtils', 'copyToFile'),
             ('org.apache.commons.io.FileUtils', 'copyURLToFile'),
             ('org.apache.commons.io.FileUtils', 'createParentDirectories'),
             ('org.apache.commons.io.FileUtils', 'delete'),
             ('org.apache.commons.io.FileUtils', 'deleteDirectory'),
             ('org.apache.commons.io.FileUtils', 'deleteQuitely'),
             ('org.apache.commons.io.FileUtils', 'forceDelete'),
             ('org.apache.commons.io.FileUtils', 'forceDeleteOnExit'),
             ('org.apache.commons.io.FileUtils', 'forceMkdir'),
             ('org.apache.commons.io.FileUtils', 'forceMkdirParent'),
             ('org.apache.commons.io.FileUtils', 'moveDirectory'),
             ('org.apache.commons.io.FileUtils', 'moveDirectoryToDirectory'),
             ('org.apache.commons.io.FileUtils', 'moveFile'),
             ('org.apache.commons.io.FileUtils', 'moveFileToDirectory'),
             ('org.apache.commons.io.FileUtils', 'moveToDirectory'),
             ('org.apache.commons.io.FileUtils', 'newOutputStream'),
             ('org.apache.commons.io.FileUtils', 'openOutputStream'),
             ('org.apache.commons.io.FileUtils', 'write'),
             ('org.apache.commons.io.FileUtils', 'writeByteArrayToFile'),
             ('org.apache.commons.io.FileUtils', 'writeLines'),
             ('org.apache.commons.io.FileUtils', 'writeStringToFile'),
             ('org.apache.commons.io.file.PathUtils', 'cleanDirectory'),
             ('org.apache.commons.io.file.PathUtils', 'copyDirectory'),
             ('org.apache.commons.io.file.PathUtils', 'copyFile'),
             ('org.apache.commons.io.file.PathUtils', 'copyFileToDirectory'),
             ('org.apache.commons.io.file.PathUtils', 'delete'),
             ('org.apache.commons.io.file.PathUtils', 'deleteDirectory'),
             ('org.apache.commons.io.file.PathUtils', 'deleteFile')]
        }
    },
    'CWE352': {
        'metadata': {
            'id': 352,
            'description': 'Cross-site Request Forgery'
        },
        'sink': {
            'c-cpp': [],
            'python':
            [('django.middleware.csrf.CsrfViewMiddleware',
              'csrf_trusted_origins_hosts'),
             ('django.middleware.csrf.CsrfViewMiddleware',
              'allowed_origins_exact'),
             ('django.middleware.csrf.CsrfViewMiddleware',
              'allowed_origin_subdomains'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_accept'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_reject'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_get_secret'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_set_csrf_cookie'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_origin_verified'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_check_referer'),
             ('django.middleware.csrf.CsrfViewMiddleware', '_check_token'),
             ('django.middleware.csrf.CsrfViewMiddleware', 'process_request'),
             ('django.middleware.csrf.CsrfViewMiddleware', 'process_view'),
             ('django.middleware.csrf.CsrfViewMiddleware', 'process_response')
             ],
            'jvm':
            [('org.springframework.security.config.annotation.web.builders.HttpSecurity',
              'csrf')]
        }
    },
    'CWE434': {
        'metadata': {
            'id': 434,
            'description': 'Unrestricted Upload of File'
        },
        'sink': {
            'c-cpp': [],
            'python': [],
            'jvm':
            [('javax.servlet.http.HttpServletRequest', 'getContentType'),
             ('javax.servlet.http.HttpServletRequest', 'getParameter'),
             ('javax.servlet.http.HttpServletRequest', 'getParameterMap'),
             ('javax.servlet.http.HttpServletRequest', 'getParameterNames'),
             ('javax.servlet.http.HttpServletRequest', 'getParameterValues'),
             ('javax.servlet.http.HttpServletRequest', 'getPart'),
             ('javax.servlet.http.HttpServletRequest', 'getParts'),
             ('java.io.InputStream', 'read'),
             ('java.io.BufferedReader', 'read'),
             ('java.io.BufferedReader', 'readLine'),
             ('java.io.BufferedWriter', 'write'),
             ('java.io.OutputStream', 'write'), ('java.lang.System', 'getenv'),
             ('java.lang.System', 'getProperties'),
             ('java.lang.System', 'getProperty'), ('java.lang.System', 'load'),
             ('java.lang.System', 'loadLibrary'),
             ('java.lang.System', 'getSecurityManager')]
        }
    }
}

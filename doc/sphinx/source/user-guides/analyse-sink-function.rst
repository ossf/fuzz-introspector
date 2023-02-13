Identify and analyse sink functions/methods
-------------------------------------------

Fuzz Introspector provides an analyser that identifies possible sink 
functions/methods from the target project and analyses them. In general
terms, a sink function/method is a function/method that may take in
tainted values or commands from a malicious user. Those tainted values
may be unintentionally executed or stored for malicious purposes. These
injection attacks could occur if the function/method does not check or
sanitize input from users. In this section, we will discuss sink
functions/methods and how Fuzz Introspector can help to find them and
aids in developing specific fuzzers to cover these sink functions that
existed in the target project.

How to enable Sink Analyser in the Fuzz Introspector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

By default, Sink Analyser is not included in the Fuzz Introspector 
processing. To enable Sink Analyser in the Fuzz Intropsector report,
please add the argument ``--analysis SinkCoverageAnalyser`` when 
executing the main method of the Fuzz Introspector. Fuzz Introspector
will then run the Sink Analyser to generate both a result table section
in the HTML report and a list in the JSON report.

Sink functions/methods handled by Fuzz Introspector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section contains the sink functions list handled by the Fuzz Introspector
Sink Analyser for the three language families C-CPP / Python / Java.


Sink function List for C language family
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. ``system``

   * It could be used to execute commands in the underlying OS with the current execution privilege.

#. ``execl`` ``execlp`` ``execle`` ``execv`` ``execvp`` ``execve``

   * It could be used to execute commands in the underlying OS with the current execution privilege.

#. ``wordexp``

   * It performs a shell-like expansion of string which could be a target of command injection.

#. ``popen``

   * It creates a subprocess with the current execution privilege.

Sink function/method list for Python language family
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. ``exec``

   * Execute a large block of python code with the current execution privilege.

#. ``eval``

   * Evaluate and execute a single python expression with the current execution privilege.

#. ``subprocess.run``

   * Create a subprocess to execute a command with the current execution privilege.

#. ``subprocess.call`` ``subprocess.check_output``

   * Older version of command execution before Python 3.5,  now similar to ``subprocess.run``.

#. ``subprocess.Popen``

   * Create a child program in a new process to execute a command with the same execution privilege.

#. ``os.system``

   * Execute commands in the underlying OS.

#. ``os.popen``

   * Create a child program in a new process to execute a command with the same execution privilege.

#. ``os.spawn`` ``os.spawnv`` ``os.spawnve`` ``os.spawnvp`` ``os.spawnvpe`` ``os.spawnl`` ``os.spawnle`` ``os.spawnlp`` ``os.spawnlpe``

   * Spawning a new process to execute a command with the same execution privilege.

#. ``os.exec`` ``os.execl`` ``os.execle`` ``os.execlp`` ``os.execlpe`` ``os.execv`` ``os.execve`` ``os.execvp`` ``os.execlpe``

   * Execute commands in the underlying OS.

#. ``asyncio.create_subprocess_shell``

   * Open a shell in a new process with the current execution privilege for execution.

#. ``asyncio.create_subprocess_exec``

   * Create a subprocess with the current execution privilege and execution given command.

#. ``asyncio.run``

   * Execute a given coroutine with the current execution privilege.

#. ``asyncio.sleep``

   * Pause the execution of a given coroutine which could be modified by an attacker for injection purpose.

#. ``logging.config.listen``

   * Listen for logging config which could be polluted with malicious configuration.

#. ``code.InteractiveInterpreter.runsource``

   * Compile and execute code which could be injected by an attacker.

#. ``code.InteractiveInterpreter.runcode``

   * Execute precompiled code which could be injected by an attacker.

#. ``code.InteractiveInterpreter.write``

   * Write a string to standard error stream which is vulnerable to command injection from breaking out of error display.

#. ``code.InteractiveConsole.push``

   * Push a new line of source code to the interpreter which could be malicious code.

#. ``code.InteractiveConsole.interact``

   * Process the source code (which may be polluted) in the interpreter and emulate the interactive python console.

#. ``code.InteractiveConsole.raw_input``

   * Write a prompt and read a line for further execution which could provide an entrance for injected code.

#. ``code.interact``

   * Read/execute and print results for given code which could be malicious.

#. ``code.compile_command``

   * Compile the given command similar to the main loop in the python interactive console.

Sink method List for Java language family
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. ``java.lang.Runtime.exec``

   * Execute given command with current privilege which could include injected code.

#. ``javax.xml.xpath.XPath.compile``

   * Compile XML path language expression which could lead to XPath injection.

#. ``javax.xml.xpath.XPath.evaluate``

   * Compile and evaluate the type of XML path language expression which could lead to XPath injection.

#. ``java.lang.Thread.run`` ``java.lang.Runnable.run`` ``java.util.concurrent.Executor.execute`` ``java.util.concurrent.Callable.call``

   * Starting a new concurrent thread to execute given commands or processes which could be polluted.

#. ``java.lang.System.console``

   * Create an OS console with current privilege for further execution which may include injected commands.

#. ``java.lang.System.load`` ``java.lang.System.loadLibrary``

   * Load given classes of libraries which could contain polluted packages.

#. ``java.lang.System.mapLibraryName``

   * It maps a library name into a platform-specific string representing a native library which could point to a polluted library package.

#. ``java.lang.System.runFinalization``

   * Execute finalize method of an object which could contain malicious commands.

#. ``java.lang.System.setErr`` ``java.lang.System.setIn`` ``java.lang.System.setOut`` ``java.lang.System.setProperties`` ``java.lang.System.setProperty``

   * Changes different system properties and settings and redirects normal execution to malicious execution.

#. ``java.lang.System.setSecurityManager``

   * Changes the security manager to alter or decrease some of the protection from later attacks.

#. ``java.lang.ProcessBuilder.directory``

   * It can set the working directory of the process and redirects to an illegal path by a manipulated string.

#. ``java.lang.ProcessBuilder.inheritIO``

   * It can set the execution source and destination of the process which could be polluted and pointed to a malicious location.

#. ``java.lang.ProcessBuilder.command``

   * It can set the OS command to be executed by the process with the current privilege which could be injected to include malicious commands.

#. ``java.lang.ProcessBuilder.redirectError`` ``java.lang.ProcessBuilder.redirectErrorStream`` ``java.lang.ProcessBuilder.redirectInput`` ``java.lang.ProcessBuilder.redirectOutput``

   * Injected input changing the default settings could redirect normal execution to malicious execution on the new process.

#. ``java.lang.ProcessBuilder.start``

   * Start the process which could contain polluted commands or sources.

Identify sink functions/methods in target project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To capture sink functions/methods Fuzz Introspector go through the complete
function list generated by the frontend analysing code for the three supported
languages. All the sink functions/methods existed in the target project are
captured and shown in the report. The report contains the list of the sink
functions/methods discovered and their relative information. This information
helps the fuzzer developers to develop fuzzers targeted to these sinks
functions/methods. These target specific fuzzers can then identifying if the
sink functions/methods handled possible tainted input securely.

HTML report
^^^^^^^^^^^

The HTML report of the Fuzz Introspector Sink Analyser shows all existing 
sink functions/methods in the target project. The table report also
contains some runtime coverage and information for each sink function/method
in the table. A sample result of the html table report for project ``libssh``
is shown below.

.. figure:: /user-guides/images/sink-analyser-html-table.png
   :width: 800px
   :alt: Sink methods table in the HTML reeport for project ``libssh``

Each row in the HTML table report represents one sink function/method discovered
in the target project. Here is a description list of the meaning of each column 
item in the table.

#. Target sink

   * The full name of the sink function/method.

#. Callsite location

   * Source file, line number and parent function of the sink function/method based on static analysis and provided by the call tree. It will display "Not in call tree" if this sink function/method is not statically reached by any fuzzers.

#. Reached by fuzzer

   * Displaying a list or empty result of fuzzers statically reaching this sink function/method.

#. Function call path

   * All call paths of the project from outermost functions/methods calling to each sink function/method. Group by functions directly invoking the sink function/method.

#. Covered by fuzzer

   * The count of fuzzers covering this sink function/method during runtime. It will display N/A if no fuzzers statically reached this sink function/method or no fuzzers invoke this sink function/method during runtime.

#. Possible branch blockers

   * If some fuzzers do statically reach the sink function/method but do not invoke them in runtime, that means that some branch blockers (functions/methods that have been invoked but fail to call down the call tree to reach the sink function/method) stop the invocation of the sink function/method. This column shows a list of possible branch blockers and their related information.


JSON output
^^^^^^^^^^^

Apart from the table section in the HTML report, Sink Analyser also includes
the result in machine-readable JSON format. The JSON report contains a JSON
list of Sink Functions and the related information similar to the HTML report.
The JSON result list is stored under the key ``SinkCoverageAnalyser`` in the ``analyses``
section within the Fuzz Introspector summary.json output which also contains 
the data from main Fuzz Introspector logic and other analysers. A sample
result for project ``libssh`` is shown below.

.. code-block:: json

    {
      ...
      "analyses": {
        ...
        "SinkCoverageAnalyser": [
          {
            "func_name": "execv",
            "call_loc": "Not in call tree",
            "fuzzer_reach": [
              "ssh_client_config_fuzzer",
              "ssh_server_fuzzer",
              "ssh_client_fuzzer",
              "ssh_bind_config_fuzzer"
            ],
            "parent_func": [
              "ssh_exec_shell",
              "ssh_execute_command"
            ],
            "callpaths": {
              "ssh_exec_shell": [
                [
                  "ssh_config_parse_string",
                  "ssh_config_parse_line",
                  "ssh_match_exec",
                  "ssh_exec_shell"
                ],
                [
                  "ssh_connect",
                  "ssh_options_parse_config",
                  "ssh_config_parse_file",
                  "ssh_config_parse_line",
                  "ssh_match_exec",
                  "ssh_exec_shell"
                ]
              ]
            },
            "fuzzer_cover": "0",
            "blocker": "<table><thead><th bgcolor='#282A36'>Blocker function</th><th bgcolor='#282A36'>Arguments type</th><th bgcolor='#282A36'>Return type</th><th bgcolor='#282A36'>Constants touched</th></thead><tbody><tr><td>ssh_exec_shell<br/>in /src/libssh/src/config.c:318</td><td>['char *']</td><td>int </td><td>[]</td></tr><tr><td>ssh_connect<br/>in /src/libssh/src/client.c:516</td><td>['struct.ssh_session_struct *']</td><td>int </td><td>[]</td></tr></tbody></table>"
          }
        ]
        ...
      }
      ...
    }

Under the ``SinkCoverageAnalyser`` key, there is a JSON list storing the Sink
Analyser result in JSON format. The data in the list follow the same results
provided in the HTML report. Each item in the list is a JSON map for each
sink function/method. The mapping keys for each column in the HTML report
are shown in the list below. One special column is the ``function call path``
column which are combined into one column for items in two JSON key.

+--------------------------+-------------------------+
| HTML column              | JSON key                |
+==========================+=========================+
| Target sink              | func_name               |
+--------------------------+-------------------------+
| Callsite location        | call_loc                |
+--------------------------+-------------------------+
| Reached by fuzzer        | fuzzer_reach            |
+--------------------------+-------------------------+
| Function call path       | parent_func / callpaths |
+--------------------------+-------------------------+
| Covered by fuzzer        | fuzzer_cover            |
+--------------------------+-------------------------+
| Possible branch blockers | blocker                 |
+--------------------------+-------------------------+

Analyse sink functions/method in target project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are three possible scenarios for fuzzers on those existing sink 
functions/methods in the target project. The first and easy scenario is
that the sink function/method is covered by at least one fuzzer both
statically and dynamically. It means that the fuzzer successfully fuzz
the target sink function/method. The other two scenarios are discussed
in the following subsections.

Analyse possible parent functions and call paths of sink functions/methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this subsection, we discuss the scenario that there exists a sink function/method
in the target project which does not have any fuzzers statically reaching it. In
general, it means that no fuzzers or any of the functions/methods have invoked the
sink function/method. This means that the sink function/method is not included in the
fuzzing target. One of the major targets of the sink analyser is aiding the developer
to write fuzzers that can cover the sink functions/methods in the project. This could
help to ensure the use of those sink functions/methods are secure against possible
injection attack. For this reason, the sink analyser provides parent functions/methods
and call path information to help developers to write fuzzers that can cover the target
sink functions.

The result is shown in column ``Function call path`` in the HTML report table and under
the ``parent_func`` and ``callpaths`` keys in the JSON report. This information tells the
developer which functions/methods in the target project directly invoke the target sink
function/method. Then it provides a list of possible call paths (a list of function/method
invocation chains) to reach that function (parent function). Following these possible paths,
developers could create specific fuzzers to reach the target sink function/method.

If the source code coverage report does exist, clicking the name of the parent function
could redirect the browser to the sink function/method invocation location in the source
code. The source file name and line number of the invocation will also be shown below
the parent function name. This could help the developer to accurately locate the invocation
of the target sink function/method. 

.. figure:: /user-guides/images/callpath-table.png
   :width: 300px
   :alt: Callpaths and parent functions for sink methods ``execv`` in the project ``libssh``
   :align: center

Clicking on the link of the ``Path X`` call path will redirect the user to a separate HTML
page which displays a call path tree for the possible call path reaching that parent
function. A sample of the separate call path tree  HTML page is shown below.

.. figure:: /user-guides/images/calltree-html-page.png
   :width: 800px
   :alt: Separate HTML page showing one of the call tree to reach the parent function ``ssh_exec_shell`` of sink function ``execv`` of project ``libssh``

For the JSON output, the list of the parent function names is included under the
``parent_func`` key. While the list of call paths to any parent functions/methods is
included under the ``callpaths`` key. Each of the call paths itself is an ordered list
of string containing the name of functions/methods invocation chain from outermost
functions/methods. The last item on the list is the name of the parent function/method
of the sink function/method.

Analyse possible blockers for sink functions/methods
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In this subsection, we discuss the scenario that there exists a sink function/method
in the target project and there is at least one fuzzer statically reaching it.
But in runtime, the fuzzer reaching the sink function/method fails to invoke it. It
could be because of wrong configurations of fuzzers or because the random data provided
to fuzzers does not go through some of the branches in the functions/methods invoke
chain to reach the target sink function/method. It is also possible that the chances of
reaching the target sink function/method are low and the fuzzers do not run long enough
to trigger the low opportunity to invoke the target sink function/method. 

Most of the reasons above do relate to the existence of blocker functions/methods.
Blocker functions/methods are the functions/methods that exist in the invoke
chain of the sink functions/methods and fail to call down the chain, thus they
"block" the invocation towards the sink functions/methods. Fuzz Introspector
Sink Analyser does provide information on these blocker functions/methods to
aid the developer to debug and fix their fuzzers to successfully invoke down
to the sink functions/methods.

In the HTML report, the list of blocker functions/methods is shown under the
``Possible branch blockers`` column. There is a separate subtable under the
column for blockers of each of the possible call paths statically reaching
the target sink functions/methods. The subtable contains 4 columns and each
column is described in the following list.

#. Blocker function

   * The name of the blocker function/method, the source file/line number of the blocker function and also a link to the source code location if the source code coverage report does exist.

#. Arguments type

   * The arguments of the block functions. This could help the developer tune the argument passed to the blocker functions.

#. Return type

   * The return type of the blocker function. This could help the developer analyse the reason why it cannot invoke down to the sink functions/methods.

#. Constants touched

   * A list of constant values used by the blocker function. This could help the developer identifies if the sink functions/methods are using some constant values as input, which may be safe from injection because the input is not touched by users.

For the JSON report, it includes the HTML of all the subtables of block functions
under the ``blocker`` key which also contains the same set of information mentioned
above for the HTML report table.

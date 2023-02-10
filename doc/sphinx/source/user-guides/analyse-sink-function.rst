Identify and analyse sink functions
-----------------------------------

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

List of sink functions handled by Fuzz Introspector
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section contains list of sink functions being discovered by the Fuzz Introspector
Sink Analyser for the three language family C-CPP / Python / Java.


Sink function List for C language family
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. system

   * It could be used to execute command in underlying OS with the current execution privilege.

#. execl, execlp, execle, execv, execvp, execve

   * It could be used to execute command in underlying OS with the current execution privilege.

#. wordexp

   * It performs a shell-like expansion of string which could be target of command injection.

#. popen

   * It create a subprocess with the current execution privilege.

Sink function List for Python language family
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. exec

   * Execute large block of python code with the current execution privilege

#. eval

   * Evaluate and execute single python expression with the current execution privilege

#. subprocess.run

   * Create a subprocess to execute a command with the current execution privilege

#. subprocess.call / subprocess.check_output

   * Older version of command execution prior to Python 3.5 / now similar to subprocess.run

#. subprocess.Popen

   * Create a child program in a new process to execute a command with same execution privilege

#. os.system

   * Execute commands in the underlying OS

#. os.popen

   * Create a child program in a new process to execute a command with same execution privilege

#. os.spawn / os.spawnv / os.spawnve / os.spawnvp / os.spawnvpe / os.spawnl / os.spawnle / os.spawnlp / os.spawnlpe

   * Spawning new process to execute a command with same execution privilege

#. os.exec / os.execl / os.execle / os.execlp / os.execlpe / os.execv / os.execve / os.execvp / os.execlpe

   * Execute commands in the underlying OS

#. asyncio.create_subprocess_shell

   * Open a shell in a new process with the current execution privilege for execution

#. asyncio.create_subprocess_exec

   * Create a subprocess with the current execution privilege and execution given command

#. asyncio.run

   * Execute a given coroutine with the current execution privilege

#. asyncio.sleep

   * Pause the execution of a given coroutine / which could be modified by an attacker for injection purpose

#. logging.config.listen

   * Listen for logging config which could be polluted with malicious configuation

#. code.InteractiveInterpreter.runsource

   * Compile and execute code which could be injected by an attacker

#. code.InteractiveInterpreter.runcode

   * Execute precomiled code which could be injected by an attacker

#. code.InteractiveInterpreter.write

   * Write string to standard error stream which are vulnarable to command injection from breaking out of error display

#. code.InteractiveConsole.push

   * Push a new line of source code to the interpretor which could be malicious code

#. code.InteractiveConsole.interact

   * Process the source code (which maybe polluted) in the interpretor and emulate the interactive python console

#. code.InteractiveConsole.raw_input

   * Write a prompt and read a line for further execution / which could provide entrance for injected code

#. code.interact

   * Read / execute and print result for given code / which could be malicious.

#. code.compile_command

   * Compile given command similar to the main loop in the python interactive console.

Sink function List for Java language family
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

#. java.lang.Runtime.exec

   * Execute given command with current privilege / which could included injected code.

#. javax.xml.xpath.XPath.compile

   * Compile XML path language expression which could lead to XPath injection.

#. javax.xml.xpath.XPath.evaluate

   * Compile and evaluate type of XML path language expression which could lead to XPath injection.

#. java.lang.Thread.run / java.lang.Runnable.run / java.util.concurrent.Executor.execute / java.util.concurrent.Callable.call

   * Starting a new concurrent thread to execute given commands or process which could be polluted.

#. java.lang.System.console

   * Create an OS console with current privilege for further execution which may include injected commands.

#. java.lang.System.load / java.lang.System.loadLibrary

   * Load given classes of libraries which could contains polluted package.

#. java.lang.System.mapLibraryName

   * It maps a library name into a platform-specific string representing a native library / which could point to a polluted library package.     

#. java.lang.System.runFinalization

   * Execute finalize method of an object which could contains malicious commands.

#. java.lang.System.setErr / java.lang.System.setIn / java.lang.System.setOut / java.lang.System.setProperties / java.lang.System.setProperty

   * Injected input changing different system properties and settings which could by injected and redirect normal execution to malicious execution.

#. java.lang.System.setSecurityManager

   * Injected input changing the security manager could alter or decrease the some of the protection from later attacks.

#. java.lang.ProcessBuilder.directory

   * It can set the working directory of the process / which could be redirect to illegal location by an injected path.

#. java.lang.ProcessBuilder.inheritIO

   * It can set the execution source and destination of the process which could be polluted and pointed to malicious source.

#. java.lang.ProcessBuilder.command

   * It can set the OS command to be executed by the process with the current privilege which could be injected to include malicious commands.

#. java.lang.ProcessBuilder.redirectError / java.lang.ProcessBuilder.redirectErrorStream / java.lang.ProcessBuilder.redirectInput / java.lang.ProcessBuilder.redirectOutput

   * Injected input changing the default settings could redirect normal execution to malicious execution on the new process.

#. java.lang.ProcessBuilder.start

   * Start the process which could contains polluted commands or source.

Identify sink functions in target project
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To capture sink functions/methods Fuzz Introspector go through the complete
function list generated by the frontend analysing code for the three supported
languages. All the sink functions/methods existed in the target project are
captured and shown in the report. The report contains the list of the sink
functions/methods discovered and their relative information. This information
helps the fuzzer developers to develop fuzzers targeted to these sinks
functions/methods. These target specific fuzzers can then identifying if the
sink functions/methods handled possible tainted input securely.

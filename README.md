# functrace - A function tracer

*functrace* is a tool that helps to analyze a binary file with dynamic instrumentation using *DynamoRIO* (<http://dynamorio.org/>).

These are some implemented features:

- [ ] disassemble all the executed code
- [ ] disassemble a specific function
- [ ] get arguments of a specific function
- [ ] get return value of a specific function
- [ ] monitors application signals
- [ ] generate a report file

## Setup

```shell
$ git clone https://github.com/invictus1306/functrace
$ mkdir build && cd build
$ cmake .. -DDynamoRIO_DIR=<path_to_dr/cmake/>
$ make -j4
```

## Using functrace

```shell
$ drrun -c libfunctrace.so -- target
```

#### Options

The following *[functrace]*(https://github.com/invictus1306/functrace) options are supported:

```latex
-disassembly                    -> disassemble all the functions 
-disas_func function_name       -> disassemble only the function function_name	
-wrap_function function_name    -> wrap the function function_name				
-wrap_function_args num_args    -> number of arguments of the wrapped function
-report_file file_name          -> report file name
-verbose                        -> verbose
```

#### Simple usage

```shell
$ drrun -c libfunctrace.so -report_file report1 -verbose -- ../tests/simple_test
Please enter a message: 
AAAA
Hello! This is the default message
```

This will be the output [report1](https://github.com/invictus1306/functrace/blob/master/tests/report1)

```shell
$ drrun -c libfunctrace.so -report_file report2 -disassembly -verbose -- ../tests/simple_test
Please enter a message: 
AAAA
Hello! This is the default message
```



This will be the output [report2](https://github.com/invictus1306/functrace/blob/master/tests/report2)

```shell
$ drrun -c libfunctrace.so -report_file ../tests/report3 -disas_func print_default -- ../tests/simple_test
Please enter a message: 
AAAA
Hello! This is the default message
```

This will be the output [report3](https://github.com/invictus1306/functrace/blob/master/tests/report3)

```shell
$ drrun -c libfunctrace.so -report_file ../tests/report4 -wrap_function print_default -wrap_function_args 0 -- ../tests/simple_test
WRAPPED function: print_default 
Please enter a message: 
AAAA
Hello! This is the default message
```

This will be the output [report4](https://github.com/invictus1306/functrace/blob/master/tests/report4)

Using [beebug](https://github.com/invictus1306/beebug) it is possible to see the reports graphically.

#### Real case - Vulnerability Analysis

From vulnerability report to a crafted packet using instrumentation [https://invictus1306.github.io/vulnerabilitis/2018/12/29/functrace.html]

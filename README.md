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

### Options

The following *[functrace]*(https://github.com/invictus1306/functrace) options are supported:

```latex
-disassembly                    -> disassemble all the functions 
-disas_func function_name       -> disassemble only the function function_name	
-wrap_function function_name    -> wrap the function function_name				
-wrap_function_args num_args    -> number of arguments of the wrapped function
-cbr                            -> remove the bb from the cache (in case of conditional jump)
-report_file file_name          -> report file name (required)
-verbose                        -> verbose
```

### Simple usage

#### Option *-verbose*
```shell
$ drrun -c libfunctrace.so -report_file report -verbose -- target_program [args]
```

#### Option *-disassemby*
```shell
$ drrun -c libfunctrace.so -report_file report -disassembly -verbose -- target_program [args]
```

#### Option *-disas_func*
```shell
$ drrun -c libfunctrace.so -report_file report -disas_func name_function -verbose -- target_program [args]
```

#### Option *-wrap_function* and *-wrap_function_args*
```shell
$ drrun -c libfunctrace.so -report_file report -wrap_function name_function -wrap_function_args num_args -- target_program [args]
```

#### Option *-cbr*
```shell
$ drrun -c libfunctrace.so -report_file report -cbr -- target_program [args]
```

Using [beebug](https://github.com/invictus1306/beebug) it is possible to see the reports graphically.

### Real case - Vulnerability Analysis

From vulnerability report to a crafted packet using instrumentation [https://invictus1306.github.io/vulnerabilitis/2018/12/29/functrace.html]

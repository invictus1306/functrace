# functrace - A function tracer

*functrace* is a tool that helps to analyze a binary file with dynamic instrumentation using *DynamoRIO* (<http://dynamorio.org/>).

These are some implemented features (based on DynamoRIO):

- [ ] disassemble all the executed code
- [ ] disassemble a specific function (dump if these are addresses)
- [ ] get arguments of a specific function (dump if these are addresses)
- [ ] get return value of a specific function (dump if this is an address)
- [ ] monitors application signals
- [ ] generate a report file
- [ ] *ghidra*(<https://ghidra-sre.org/>) coverage script (based on the functrace report file)

## Setup

```shell
$ wget https://github.com/DynamoRIO/dynamorio/releases/download/release_7_0_0_rc1/DynamoRIO-Linux-7.0.0-RC1.tar.gz
$ tar xvzf DynamoRIO-Linux-7.0.0-RC1.tar.gz
$ git clone https://github.com/invictus1306/functrace
$ mkdir -p functrace/build
$ cd functrace/build
$ cmake .. -DDynamoRIO_DIR=/full_DR_path/DynamoRIO-Linux-7.0.0-RC1/cmake/
$ make -j4
```
## Simple DEMO

![functrace](https://github.com/invictus1306/functrace/blob/master/images/functrace.gif)

## Using functrace

```shell
$ drrun -c libfunctrace.so -report_file report -- target_program [args]
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
$ drrun -c libfunctrace.so -report_file report -disassembly -- target_program [args]
```

#### Option *-disas_func*
```shell
$ drrun -c libfunctrace.so -report_file report -disas_func name_function -- target_program [args]
```

#### Option *-wrap_function* and *-wrap_function_args*
```shell
$ drrun -c libfunctrace.so -report_file report -wrap_function name_function -wrap_function_args num_args -- target_program [args]
```

#### Option *-cbr*
```shell
$ drrun -c libfunctrace.so -report_file report -cbr -- target_program [args]
```

### CVE-2018-4013 - Vulnerability Analysis

A vulnerability on the [LIVE555 RTSP](http://www.live555.com/) server library. This is the [description](https://www.cvedetails.com/cve/CVE-2018-4013/).

![vulnanalysis](https://github.com/invictus1306/functrace/blob/master/images/CVE-2018-4013.gif)

## Working enviroment
Tested on Ubuntu 16.04.5 LTS 64 bit

## Future features
* Ghidra plugin
* Visual setup interface
* Store and compare different coverage analysis
* Run DR directy
* Add more functionality to functrace
* Support for Android

# JXPerf

Java inefficiency detection tool based on CPU performance monitoring counters and hardware debug registers. The tool detects dead writes, silent stores, redundant loads, and memory bloat.

![build master](https://github.com/Xuhpclab/jxperf/workflows/build%20master/badge.svg)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/42f3be52e8a04bd19f3be986f660600e)](https://app.codacy.com/gh/Xuhpclab/jxperf?utm_source=github.com&utm_medium=referral&utm_content=Xuhpclab/jxperf&utm_campaign=Badge_Grade_Dashboard)
![license](https://img.shields.io/github/license/Xuhpclab/jxperf)

## Contents

- [Installation](#installation)
- [Usage](#usage)
- [Support Platforms](#support-platforms)
- [Support JDK Versions](#support-jdk-versions)
- [License](#license)

## Installation

### Linux

#### 1. Installation Prerequisites

* Install Oracle/OpenJDK and Apache Maven.
* cp set_env.template set_env
* Modify set_env to make JXPerf_HOME, JAVA_HOME and MAVEN_HOME point to your JXPerf, Java and Maven home.
* source set_env

#### 2. Installation
```console
$ make
```

#### 3. Uninstallation
```console
$ make clean
```

## Usage

### Linux

#### 1. To run dead store detection
* **Start Profiler**
```console
$ LD_PRELOAD=$JXPerf_HOME/build/libpreload.so java -agentpath:$JXPerf_HOME/build/libagent.so=DeadStore::MEM_UOPS_RETIRED:ALL_STORES:precise=2@<sampling rate> -cp <classpath> <java program>
```
* **Generate profiling results "agent-data"**
```console
$ python $JXPerf_HOME/script/process_raw_data.py
```

#### 2. To run silent store detection
* **Start Profiler**
```console
$ LD_PRELOAD=$JXPerf_HOME/build/libpreload.so java -agentpath:$JXPerf_HOME/build/libagent.so=SilentStore::MEM_UOPS_RETIRED:ALL_STORES:precise=2@<sampling rate> -cp <classpath> <java program>
```
* **Generate profiling results "agent-data"**
```console
$ python $JXPerf_HOME/script/process_raw_data.py
```

#### 3. To run silent load detection
* **Start Profiler**
```console
$ LD_PRELOAD=$JXPerf_HOME/build/libpreload.so java -agentpath:$JXPerf_HOME/build/libagent.so=SilentLoad::MEM_UOPS_RETIRED:ALL_LOADS:precise=2@<sampling rate> -cp <classpath> <java program>
```
* **Generate profiling results "agent-data"**
```console
$ python $JXPerf_HOME/script/process_raw_data.py
```

#### 4. To run data centric analysis
* **Start Profiler**
```console
$ LD_PRELOAD=$JXPerf_HOME/build/libpreload.so java -javaagent:$JAVA_AGENT -agentpath:$JXPerf_HOME/build/libagent.so=DataCentric::MEM_LOAD_UOPS_RETIRED:L1_MISS:precise=2@<sampling rate> -cp <classpath> <java program>
```
* **Generate profiling results "agent-data"**
```console
$ python $JXPerf_HOME/script/process_raw_data.py
```
* The "agent_data" includes two metrics: "Allocation Times" and "L1 Cache Misses"
  * The metric "Allocation Times" reports allocation times for every object, which is represented with the object allocation site
  * The metric "L1 Cache Misses" reports a pair of calling context (i.e., <allocation site, access site>) for every object incurring L1 cache misses
  * To analyze memory bloat
    * Identify the objects suffering from high L1 cache misses by looking into the metric "L1 Cache Misses"
    * Check whether these objects have high allocation times by looking into the metric "Allocation Times"
    * The objects having both high L1 cache misses and allocation times are primary optimization candidates

#### 5. Attach to a running JVM
* Open run_attach.sh and change MODE to one of below modes:
  * DataCentric::MEM_LOAD_UOPS_RETIRED:L1_MISS:precise=2@`<sampling rate>`
  * DeadStore::MEM_UOPS_RETIRED:ALL_STORES:precise=2@<sampling rate>
  * SilentStore::MEM_UOPS_RETIRED:ALL_STORES:precise=2@<sampling rate>
  * SilentLoad::MEM_UOPS_RETIRED:ALL_LOADS:precise=2@<sampling rate>
* **Start Profiler**
```console
$ ./run_attach.sh <pid> <running time in seconds>
```
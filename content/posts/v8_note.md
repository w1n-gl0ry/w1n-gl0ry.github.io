---
title: "V8 note"
date: 2024-04-15T17:37:11+08:00
toc: true
description: Writeup
tags: ["ctf", "pwn"]
draft: false
---

## V8 note
## C++ Intro

### V8
+ Google's open source JavaScript engine
+ Used for interpret and execute JS code
+ Implemented in C++
+ Parse JS code, construct AST, JIT compiled AST into assembly for execution

![image](https://hackmd.io/_uploads/S1HHRcmeA.png)


### Compiler and optimization for v8

+ Have 4 internal compilers
+ The old baseline compiler: Full-Codegen.
+ The old optimizing compiler: Crankshaft.
+ The new optimizing compiler: TurboFan.
+ The new baseline compiler: Ignition.

![image](https://hackmd.io/_uploads/Hk3XrB2yR.png)


### Compiler History

+ Full-Codegen : directly generates and executes assembly language from AST

=> It is relatively fast, but the generated assembly language code has many redundant parts and there is room for optimization.

+ Crankshaft : was introduced in 2010 to optimize code.

![image](https://hackmd.io/_uploads/rJecIB2JR.png)

+ TurboFan : was introduced in 2015 to better adapt to the new JavaScript specification.
![image](https://hackmd.io/_uploads/rkd6Irn1C.png)

+ Ignition : introduced in 2017, which generates intermediate language (bytecode)

![image](https://hackmd.io/_uploads/ry2mwrnyC.png)

* Since 2018, Full-Codegen and Crankshaft have been removed from v8.

![image](https://hackmd.io/_uploads/SkaHDH3J0.png)

### Abstract syntax tree

![image](https://hackmd.io/_uploads/ry0Kwr210.png)

### Compiler && Optimization

* Baseline compiler : Full-Codege
* Optimization mechanism : Hidden Class, Inline Caching
* Optimizing compiler: Crankshaft, TurboFan 

* TurboFan 

    ![image](https://hackmd.io/_uploads/r1b2nH21C.png)


* Optimization mechanisms

    + Optimization 1: Cache usage
        +  Hidden Class
            * The value of each property is managed in the form of an array
        +  Inline Caching
    + Optimization 2: Recompile to more efficient JIT code
        + Crankshaft
        + TurboFan
        + Optimization goals are determined at runtime

#### Hidden Class

* properties can easily be added or removed from an object after its instantiation
    ```js
    var car = function(make,model) {
        this.make = make;
        this.model = model;
    }

    var myCar = new car(honda,accord);

    myCar.year = 2005;

    ```
=> Slower than orther languages


* Once the new function is declared, Javascript will create hidden class C0.

    ```js
    function Point(x,y) {
        this.x = x;
        this.y = y;
    }

    var obj = new Point(1,2);
    ```

    ![image](https://hackmd.io/_uploads/r1LW_LhJC.png)

* Once the first statement “this.x = x” is executed, V8 will create a second hidden class called C1 that is based on C0
 
    ![image](https://hackmd.io/_uploads/SJRRdU31C.png)

=> Everytime a new property is added to an object, the objects old hidden class is updated with a transition path to the new hidden class


* This process is repeated when the statement “this.y = y” is executed

    ![image](https://hackmd.io/_uploads/H1PrYIh10.png)


* Hidden class transitions are dependent on the order in which properties are added to an object


    ![image](https://hackmd.io/_uploads/r12pY82k0.png)


#### Inline Caching (future)
     
#### Garbage Collection (future)
    

## Build V8

+ depot_tools

    ```
    git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
    vim /etc/profile
    Add `export PATH=$PATH:"/path/to/depot_tools"` to `.profile`
    cd /depot_tools && ./gclient
    ```

+ ninja

    ```
    git clone https://github.com/ninja-build/ninja.git
    cd ninja && ./configure.py --bootstrap && cd ..
    vim /etc/profile
    Add `export PATH=$PATH:"/path/to/ninja"` to `.profile`
    source /etc/profile
    ```

+ v8 source code

    ```
    fetch v8
    ```
+ patch & compile debug version

    ```
    cd v8
    # git checkout ???
    git reset --hard +hash
    gclient sync

    #apply patch
    git apply < "path/to/tctf.diff"

    tools/dev/v8gen.py x64.debug
    ninja -C out.gn/x64.debug
    #the result is in /out.gn/x64.debug/d8
    #./tools/dev/gm.py x64.debug
    ```

+ Build with natives_blob.bin and snapshot_blob.bin
    
    ```
    v8_static_library = true
    v8_use_snapshot = true
    v8_use_external_startup_data = true
    ```
+ add gdb extension

    ```
    source /path/to/v8/tools/gdbinit
    source /path/to/v8/tools/gdb-v8-support.py
    ```
    
+ Debug

    ```
    %DebugPrint(a);
    %SystemBreak(); 
    %CollectGarbage(); # trigger garbage collection
    %OptimizeFunctionOnNextCall(); # force JIT compilation of a function
    ```

+ Use native syntax

    ```
    --trace-turbo
    --trace-opt
    --trace-deopt
    --trace-turbo-reduction
    ```
    
## V8 datatypes

### Values
+ dynamically typed language
+ accomplished through a combination of pointer tagging and the use of dedicated type information objects, called Maps.
+ JS data types in v8 are listed in "src/object.h"

    ```c++
    // Inheritance hierarchy:
    // - Object
    //   - Smi          (immediate small integer)
    //   - HeapObject   (superclass for everything allocated in the heap)
    //     - JSReceiver  (suitable for property access)
    //       - JSObject
    //         - JSArray
    //         - JSArrayBuffer
    //         - JSArrayBufferView
    //           - JSTypedArray
    //           - JSDataView
    //         - JSBoundFunction
    //         - JSCollection
    //           - JSSet
    //           - JSMap
    //         - JSStringIterator
    //         - JSSetIterator
    //         - JSMapIterator
    //         - JSWeakCollection
    //           - JSWeakMap
    //           - JSWeakSet
    //         - JSRegExp
    //         - JSFunction
    //         - JSGeneratorObject
    //         - JSGlobalObject
    //         - JSGlobalProxy
    //         - JSValue
    //           - JSDate
    //         - JSMessageObject
    //         - JSModuleNamespace
    //         - JSV8BreakIterator     // If V8_INTL_SUPPORT enabled.
    ...
    ```
+ Notice: A JavaScript value is then represented as a tagged pointer of static type Object*
    * On 32-bit archs:
    ```
        // Formats of Object::ptr_:
    //  Smi:        [31 bit signed int] 0
    //  HeapObject: [32 bit direct pointer] (4 byte aligned) | 01
    ```
    * On 64-bit archs:
    ```
        Smi:        [32 bit signed int] [31 bits unused] 0
        HeapObject: [64 bit direct pointer]            | 01
    ```

    => All accesses to data members of a HeapObject have to go through special accessors that take care of clearing the LSB.
    
### Maps

+ key data structure in v8, containing information such as: 

    * The dynamic type of the object, i.e. String, Uint8Array, HeapNumber, ...
    * The size of the object in bytes
    * The properties of the object and where they are stored
    * The type of the array elements, e.g. unboxed doubles or tagged pointers
    * The prototype of the object if any

+ In general there are three different regions in which property values can be stored:
    
    1) inside the object itself ("inline properties")
    2) dynamically sized heap buffer ("out-of-line properties")
    3) if the property name is an integer index [4], as array elements in a dynamically-sized heap array
    
* In 1 & 2, the Map will store the slot number of the property value while in the last case the slot number is the element index.

* Example: 

    ```js
        let o1 = {a: 42, b: 43};
        let o2 = {a: 1337, b: 1338};
    ```
    * There will be two JSObjects and one map in memory :    
    ![image](https://hackmd.io/_uploads/rydOqtXxR.png)
        
    => The Map mechanism is also essential for garbage collection: when the collector processes an allocation (a HeapObject), it can immediately retrieve information such as the object's size and whether the object contains any other tagged pointers that need to be scanned by inspecting the Map.
    
### SMI

+ 31-bit signed integer (max: 0xFFFFFFFE)
+ if pass around the number > 31-bit singed integer, V8 has to create a box: the number is turned into a double, an object is created and the double is put inside of it.

    ![image](https://hackmd.io/_uploads/S1w4J9meA.png)
    

### Objects

+ An object is a collection of properties: key-value pairs

    ![image](https://hackmd.io/_uploads/Sy_Ayq7x0.png)

+ When an object 'obj' is created, V8 creates a new JS Object and allocates memory for it. The value of 'obj' is the pointer to this JS Object.


    ![image](https://hackmd.io/_uploads/By6ngq7eA.png)
    
+ A JS Object is composed of:

    + Map: a pointer to the hidden class the object belongs to.
    + Properties: a pointer to an object containing named properties. Properties added after initialization of the object are added to the Properties store.
    + Elements: a pointer to an object containing numbered properties.
    + In-Object Properties/Fast properties: pointers to named properties defined at object initialization. The number of in-objects properties depend on the object.

    ![image](https://hackmd.io/_uploads/ry5Tl97gC.png)
    
    ![image](https://hackmd.io/_uploads/By4vWqQgA.png)


### Properties

+ JavaScript objects can have arbitrary properties associated with them. The names of object properties (or keys) can contain any character and are always strings. Any name used as a property key that is not a string is stringified via .toString() method. Thus, obj["1"] and obj[1] are equal.

    + numbered (or indexed) properties
    + named properties

### Elements: numbered properties

* If the property key is a non-negative integer (0, 1, 2, etc), the property will be stored in the "Elements" object. These properties are called elements.

#### Elements kind

` const a = [1, 2, 3]; `

* The elements kind of the array 'a' is PACKED_SMI_ELEMENTS. 

* When adding a floating-point number to the same array, V8 changes its elements kind to PACKED_DOUBLE_ELEMENTS.

* When adding a string literal to the same array, V8 changes again its elements kind to PACKED_ELEMENTS.

    ```
    const a = [1, 2, 3];    // elements kind: PACKED_SMI_ELEMENTS
    a.push(4.5);            // elements kind: PACKED_DOUBLE_ELEMENTS
    a.push('a');            // elements kind: PACKED_ELEMENTS
    ```

### Named properties

* If the property key is not a non-negative integer, the property will be stored as an Inline-Object Property or in the "Properties" object.

* The Properties store is an object that can be either a Fixed Array or a Dictionary.


#### Fast properties
    
* When the number of properties is low, the Properties store is defined as an Array by V8. 


![image](https://hackmd.io/_uploads/SJoep5mlC.png)

    
#### Slow properties

* However, if many properties get added and deleted from an object, it can result in significant time and memory overhead to maintain the descriptor array and hidden classes. 


![image](https://hackmd.io/_uploads/B1xWTq7eA.png)

    

### Primitive Types


#### Number


![image](https://hackmd.io/_uploads/SJCvq9mx0.png)
    
+ 'a' is directly stored in the memory as a SMI.

![image](https://hackmd.io/_uploads/BkFs557x0.png)

+ variable 'b' is a pointer that points to a Map with the type *_NUMBER_TYPE.


#### Strings

![image](https://hackmd.io/_uploads/H14R95QxC.png)

+ A string variable points to a Map with the type *_STRING_TYPE.

#### Boolean

![image](https://hackmd.io/_uploads/HJ4ej5Xl0.png)

* A boolean variable points to a Map with the type ODDBALL_TYPE.

#### Symbols

![image](https://hackmd.io/_uploads/rkkGjcQlC.png)

* A symbol variable points to a Symbol structure.

#### Undefined

![image](https://hackmd.io/_uploads/rklSjqmlA.png)

* An undefined variable points to a Map with type ODDBALL_TYPE.

#### Null

    
![image](https://hackmd.io/_uploads/H1xYj9QlC.png)


* A null variable points to a map with type ODDBALL_TYPE.


* In Javascript, the memory management is done by V8 and its garbage collector. 


## TurboFan - The optimizing compiler inside V8 (future)


## JIT (future)


## V8 Heap Sandbox





## References

[https://juejin.cn/post/6844903937787559944](https://juejin.cn/post/6844903937787559944)
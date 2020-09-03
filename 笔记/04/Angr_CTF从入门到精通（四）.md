# Angr_CTF从入门到精通完结篇（四）

> PS：打国赛、强网杯开学七七八八的杂事拖延了一点时间，拖更一下，上次提到的API变化可以查看一下附录

承接上一篇文章，上一章教程我们主要学习了angr的Hook接口的利用，这次我们把剩下的题目一网打尽

## 12_angr_veritesting

如题主要学习使用`Veritesting`的技术解决路径爆炸问题

### Veritesting

动态符号执行（DSE）和静态符号执行（SSE）一个为路径生成公式，一个为语句生成公式。前者生成公式时会产生很高的负载，但生成的公式很容易解；后者生成公式很容易，公式也能覆盖更多的路径，但是公式更长更难解。方法上的区别在于DSE会摘要路径汇合点上两条分支的情况，而SSE为两条分支fork两条独立的执行路径

SSE目前还不能对大规模的程序分析（如Cloud9+state merging），问题主要在于循环的表示、方程复杂度、缺少具体状态、和对syscall等的模拟。Veritesting可以在SSE和DSE之间切换，减少负载和公式求解难度，并解决静态方法需要摘要或其他方法才能处理的系统调用和间接跳转

简单来说就是Veritesting结合了静态符合执行与动态符号执行，减少了路径爆炸的影响，在angr里我们只要在构造模拟管理器时，启用Veritesting了就行

```python
project.factory.simgr(initial_state, veritesting=True)
```

首先检测一下文件：

```bash
zxy@ubuntu:~/Desktop/TEMP$ checksec 12_angr_veritesting
[*] '/home/syc/Desktop/TEMP/12_angr_veritesting'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用IDA打开查看一下函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char **v3; // ST1C_4
  int v4; // ST08_4
  int v5; // ebx
  int v7; // [esp-10h] [ebp-5Ch]
  int v8; // [esp-Ch] [ebp-58h]
  int v9; // [esp-8h] [ebp-54h]
  int v10; // [esp-4h] [ebp-50h]
  int v11; // [esp+4h] [ebp-48h]
  int v12; // [esp+8h] [ebp-44h]
  int v13; // [esp+Ch] [ebp-40h]
  int v14; // [esp+10h] [ebp-3Ch]
  int v15; // [esp+10h] [ebp-3Ch]
  int v16; // [esp+14h] [ebp-38h]
  signed int i; // [esp+14h] [ebp-38h]
  int v18; // [esp+18h] [ebp-34h]
  int string; // [esp+1Ch] [ebp-30h]
  int v20; // [esp+20h] [ebp-2Ch]
  int v21; // [esp+24h] [ebp-28h]
  int v22; // [esp+28h] [ebp-24h]
  int v23; // [esp+2Ch] [ebp-20h]
  int v24; // [esp+30h] [ebp-1Ch]
  unsigned int v25; // [esp+40h] [ebp-Ch]
  int *v26; // [esp+44h] [ebp-8h]

  v26 = &argc;
  v3 = argv;
  v25 = __readgsdword(0x14u);
  print_msg();
  memset((char *)&string + 3, 0, 0x21u);
  printf("Enter the password: ");
  __isoc99_scanf(
    "%32s",
    (char *)&string + 3,
    v4,
    v7,
    v8,
    v9,
    v10,
    v3,
    v11,
    v12,
    v13,
    v14,
    v16,
    v18,
    string,
    v20,
    v21,
    v22,
    v23,
    v24);
  v15 = 0;
  for ( i = 0; i <= 31; ++i )
  {
    v5 = *((char *)&string + i + 3);
    if ( v5 == complex_function(87, i + 186) )
      ++v15;
  }
  if ( v15 != 32 || (_BYTE)v25 )
    puts("Try again.");
  else
    puts("Good Job.");
  return 0;
}
```

```c
int __cdecl complex_function(signed int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (a1 - 65 + 47 * a2) % 26 + 65;
}
```

回忆一下`08_angr_constraints`我们很快就能发现容易产生路径爆炸的地方

```c
for ( i = 0; i <= 31; ++i )
  {
    v5 = *((char *)&string + i + 3);
    if ( v5 == complex_function(87, i + 186) )
      ++v15;
  }
```

在之前我们是通过增加条件约束和Hook函数避免路径爆炸，我们也可以尝试一下使用之前的方法，但是这题我们启用了Veritesting就变得简单了很多，不用过多的手动设定太多参数

话不多说，先直接上EXP：

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./12_angr_veritesting" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()
    simulation = project.factory.simgr(initial_state, veritesting=True)

    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        if b'Good Job.\n' in stdout_output:
            return True
        else: 
            return False

    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        if b'Try again.\n' in  stdout_output:
            return True
        else: 
            return False

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            solution = solution_state.posix.dumps(0)
            print("[+] Success! Solution is: {0}".format(solution))
            #print(scanf0_solution, scanf1_solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
```

查看一下运行结果：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200818201017.png)

其实这题就是体验一下Veritesting的强大功能

## 13_angr_static_binary

这题如题就是主要学习如何使用angr解出静态编译的题目，学习如何Hook静态库函数

### 静态编译

不同于动态编译是将应用程序需要的模块都编译成动态链接库，启动程序（初始化）时，这些模块不会被加载，运行时用到哪个模块就调用哪个。静态编译就是在编译时，把所有模块都编译进可执行文件里，当启动这个可执行文件时，所有模块都被加载进来，反映在现实中就是程序体积会相对大一些，在IDA中会发现所有用到函数都是静态编译好的

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200818214519.png)

我们先检查一下文件：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 13_angr_static_binary
[*] '/home/syc/Desktop/TEMP/13_angr_static_binary'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

拖进IDA查看一下函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [esp+1Ch] [ebp-3Ch]
  signed int j; // [esp+20h] [ebp-38h]
  char s1[20]; // [esp+24h] [ebp-34h]
  char s2[4]; // [esp+38h] [ebp-20h]
  int v8; // [esp+3Ch] [ebp-1Ch]
  unsigned int v9; // [esp+4Ch] [ebp-Ch]

  v9 = __readgsdword(0x14u);
  print_msg();
  for ( i = 0; i <= 19; ++i )
    s2[i] = 0;
  *(_DWORD *)s2 = 'NVJL';
  v8 = 'UAPE';
  printf("Enter the password: ");
  _isoc99_scanf("%8s", s1);
  for ( j = 0; j <= 7; ++j )
    s1[j] = complex_function(s1[j], j);
  if ( !strcmp(s1, s2) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

```c#
int __cdecl complex_function(signed int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (37 * a2 + a1 - 65) % 26 + 65;
}
```

通常，Angr会自动地用工作速度快得多的simprocedure代替标准库函数，但是这题中库函数都已经因为静态编译成了静态函数了，angr没法自动替换。要解决这题，需要手动Hook所有使用标准库的C函数，angr已经在simprocedure中为我们提供了这些静态函数, 这里列举一些常用的函数

```python
angr.SIM_PROCEDURES['libc']['malloc']
angr.SIM_PROCEDURES['libc']['fopen']
angr.SIM_PROCEDURES['libc']['fclose']
angr.SIM_PROCEDURES['libc']['fwrite']
angr.SIM_PROCEDURES['libc']['getchar']
angr.SIM_PROCEDURES['libc']['strncmp']
angr.SIM_PROCEDURES['libc']['strcmp']
angr.SIM_PROCEDURES['libc']['scanf']
angr.SIM_PROCEDURES['libc']['printf']
angr.SIM_PROCEDURES['libc']['puts']
angr.SIM_PROCEDURES['libc']['exit']
```

我们只需要手动找到程序中用到静态函数的地址，将其利用simprocedure提供的函数Hook掉即可

话不多说上EXP：

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./13_angr_static_binary" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
    project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
    project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
    project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())

    simulation = project.factory.simgr(initial_state, veritesting=True)

    def is_successful(state):
        stdout_output = state.posix.dumps(1)
        if b'Good Job.\n' in stdout_output:
            return True
        else: 
            return False

    def should_abort(state):
        stdout_output = state.posix.dumps(1)
        if b'Try again.\n' in  stdout_output:
            return True
        else: 
            return False

    simulation.explore(find=is_successful, avoid=should_abort)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            solution = solution_state.posix.dumps(0)
            print("[+] Success! Solution is: {0}".format(solution))
            #print(scanf0_solution, scanf1_solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
```

运行一下查看结果：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200819172721.png)

这题解题真正需要用的函数也就`printf`，`scnaf`，`puts`，即完成了angr需要的输出、输入、路径选择的功能，我们手动找到这几个函数的地址

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200819173153.png)

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200819173251.png)

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200819173332.png)

这里比较容易忽略的一个函数就是`__libc_start_main`

让我们回忆一下在linux下一个c程序是如何启动的：

1. execve 开始执行
2. execve 内部会把bin程序加载后，就把.interp指定的 动态加载器加载
3. 动态加载器把需要加载的so都加载起来，特别的把 libc.so.6 加载
4. 调用到libc.so.6里的__libc_start_main函数，真正开始执行程序
5. libc_start_main做了一些事后，调用到main()函数

所以程序是一定需要用到`__libc_start_main`，分析后得到地址：0x8048D10，于是得到代码：

```python
project.hook(0x804ed40, angr.SIM_PROCEDURES['libc']['printf']())
project.hook(0x804ed80, angr.SIM_PROCEDURES['libc']['scanf']())
project.hook(0x804f350, angr.SIM_PROCEDURES['libc']['puts']())
project.hook(0x8048d10, angr.SIM_PROCEDURES['glibc']['__libc_start_main']())
```

其它的部分和之前做过的`02_angr_find_condition`一致，不再赘述

## 14_angr_shared_library

这题如题主要是学习如何使用angr求解函数是外部导入在动态库(.so)里的题目，这题我们有了两个文件，一个是主程序`14_angr_shared_library`，另一个就是库文件`lib14_angr_shared_library.so`

我们先来检查一下这两个文件：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 14_angr_shared_library
[*] '/home/syc/Desktop/TEMP/14_angr_shared_library'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec lib14_angr_shared_library.so
[*] '/home/syc/Desktop/TEMP/lib14_angr_shared_library.so'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

我们用IDA打开这个文件，看一看函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1Ch] [ebp-1Ch]
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  memset(&s, 0, 0x10u);
  print_msg();
  printf("Enter the password: ");
  __isoc99_scanf("%8s", &s);
  if ( validate(&s, 8) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

这题特殊就特殊在这个关键的`validate`函数，我们在IDA分析`14_angr_shared_library`时点击进去看发现无法查看源代码：

```c
int __cdecl validate(int a1, int a2)
{
  return validate(a1, a2);
}
```

原因很简单，`validate`是一个外部导入函数，其真正的二进制代码不在源程序里，在它所处的库文件`lib14_angr_shared_library.so`里面

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200819202222.png)

我们用IDA打开并分析库文件`lib14_angr_shared_library.so`，找到了`validate`函数的具体实现

```c
_BOOL4 __cdecl validate(char *s1, int a2)
{
  char *v3; // esi
  char s2[4]; // [esp+4h] [ebp-24h]
  int v5; // [esp+8h] [ebp-20h]
  int j; // [esp+18h] [ebp-10h]
  int i; // [esp+1Ch] [ebp-Ch]

  if ( a2 <= 7 )
    return 0;
  for ( i = 0; i <= 19; ++i )
    s2[i] = 0;
  *(_DWORD *)s2 = 'GKLW';
  v5 = 'HWJL';
  for ( j = 0; j <= 7; ++j )
  {
    v3 = &s1[j];
    *v3 = complex_function(s1[j], j);
  }
  return strcmp(s1, s2) == 0;
}
```

```c
int __cdecl complex_function(signed int a1, int a2)
{
  if ( a1 <= 64 || a1 > 90 )
  {
    puts("Try again.");
    exit(1);
  }
  return (41 * a2 + a1 - 65) % 26 + 65;
}
```

其实和之前的题目并没有什么太大的不同，关键在于如果让angr处理这个外部导入函数

### 动态链接

要详细了解，这里推荐阅读《程序员的自我修养——链接、装载与库》

在Linux下使用GCC将源码编译成可执行文件的过程可以分解为4个步骤，分别是预处理（Prepressing）、编译（Compilation）、汇编（Assembly）和链接（Linking）。一个简单的hello word程序编译过程如下：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/261737366704808.jpg)

动态链接的基本思想是把程序按照模块拆分成相对独立的部分，在程序运行时才将它们链接在一起形成一个完整的程序，而不是像静态链接一样把所有的程序模块都连接成一个单独的可执行文件。ELF动态链接文件被称为动态共享对象（DSO，Dynamic Shared Object），简称共享对象，它们一般都是.so为扩展名的文件。相比静态链接，动态链接有两个优势，一是共享对象在磁盘和内存只有一份，节省了空间；二是升级某个共享模块时，只需要将目标文件替换，而无须将所有的程序重新链接

共享对象的最终装载地址在编译时是不确定的，而是在装载时，装载器根据当前地址空间的空闲情况，动态分配一块足够大小的虚拟地址空间给相应的共享对象。为了能够使共享对象在任意地址装载，在连接时对所有绝对地址的引用不作重定位，而把这一步推迟到装载时再完成，即装载时重定位

这题我们简单理解共享库都是是用位置无关的代码编译的，我们需要指定基址。共享库中的所有地址都是base + offset，其中offset是它们在文件中的偏移地址

我们现在先上EXP，然后再逐步分析：

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./lib14_angr_shared_library.so" 

    base = 0x4000000
    project = angr.Project(path_to_binary, load_options={ 
        'main_opts' : { 
        'custom_base_addr' : base 
        } 
    })

    buffer_pointer = claripy.BVV(0x3000000, 32)

    validate_function_address = base + 0x6d7
    initial_state = project.factory.call_state(validate_function_address, buffer_pointer, claripy.BVV(8, 32))

    password = claripy.BVS('password', 8*8)
    initial_state.memory.store(buffer_pointer, password)

    simulation = project.factory.simgr(initial_state)

    success_address = base + 0x783
    simulation.explore(find=success_address)

    if simulation.found:
        for i in simulation.found:
            solution_state = i
            solution_state.add_constraints(solution_state.regs.eax != 0)
            solution = solution_state.solver.eval(password,cast_to=bytes)
            print("[+] Success! Solution is: {0}".format(solution))
            #print(scanf0_solution, scanf1_solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
```

运行一下查看：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200819220653.png)

这题直接对库文件`lib14_angr_shared_library.so`进行符号执行求解,但问题在于库文件是需要装载才能运行的，无法单独运行，于是我们需要指定基地址

还记得我们查看的程序信息嘛

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 14_angr_shared_library
[*] '/home/syc/Desktop/TEMP/14_angr_shared_library'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

这题是没有开启PIE，所以加载基地址是不会变化的，我们可以直接设定0x8048000

### pre-binary 选项

如果你想要对一个特定的二进制对象设置一些选项，CLE也能满足你的需求在加载二进制文件时可以设置特定的参数，使用 `main_opts` 和 `lib_opts` 参数进行设置。

- `backend` - 指定 backend
- `base_addr` - 指定基址
- `entry_point` - 指定入口点
- `arch` - 指定架构

示例如下：

```python
>>> angr.Project('examples/fauxware/fauxware', main_opts={'backend': 'blob', 'arch': 'i386'}, lib_opts={'libc.so.6': {'backend': 'elf'}})
<Project examples/fauxware/fauxware>
```

参数`main_opts`和`lib_opts`接收一个以python字典形式存储的选项组。`main_opts`接收一个形如{选项名1：选项值1，选项名2：选项值2……}的字典，而`lib_opts`接收一个库名到形如{选项名1:选项值1，选项名2:选项值2……}的字典的映射。

> lib_opts是二级字典，原因是一个二进制文件可能加载多个库，而main_opts指定的是主程序加载参数，而主程序一般只有一个，因此是一级字典。

这些选项的内容因不同的后台而异，下面是一些通用的选项：

- backend —— 使用哪个后台，可以是一个对象，也可以是一个名字(字符串)
- custom_base_addr —— 使用的基地址
- custom_entry_point —— 使用的入口点
- custom_arch —— 使用的处理器体系结构的名字

所以我们可以得到脚本的第一部分

```python
path_to_binary = "./lib14_angr_shared_library.so" 
base = 0x8048000
project = angr.Project(path_to_binary, load_options={ 
		'main_opts' : { 
        'custom_base_addr' : base 
	} 
})
```

我们这里调用的是使用`.call_state`创建 state 对象，构造一个已经准备好执行`validate`函数的状态，所以我们需要设定好需要传入的参数。先回顾一下`validate`函数的原型

```c
validate(char *s1, int a2)
```

我们可以通过 `BVV(value,size)` 和 `BVS( name, size)` 接口创建位向量，先创建一个缓冲区buffer作为参数`char *s1`，因为设定的缓冲区地址在0x3000000，又因为32位程序里int类型为4字节，即32比特，故得

```python
buffer_pointer = claripy.BVV(0x3000000, 32)
```

然后从IDA中不难得出`validate`的偏移量为0x6D7，然后因为需要比较的字符串长度为8，故利用BVV传入参数`int a2`，最后得到

```python
buffer_pointer = claripy.BVV(0x3000000, 32)
validate_function_address = base + 0x6d7
initial_state = project.factory.call_state(validate_function_address, buffer_pointer, claripy.BVV(8, 32))
```

然后利用BVS创建一个符号位向量，作为符号化的传入字符串传入我们之前设定好的缓冲区地址中，这里继续利用`memory.store`接口

```python
password = claripy.BVS('password', 8*8)
initial_state.memory.store(buffer_pointer, password)
```

这里判断我们路径正确的方法有两种

- 同我们之前Hook部分一样，Hook判断部分
- 搜索函数执行完的返回地址，然后根据诺正确则EAX的值不为0，添加约束条件求解

这里我们选用了第二种方式

```python
success_address = base + 0x783
simulation.explore(find=success_address)
```

之后的部分同之前的题目类似，不再赘述

## 15_angr_arbitrary_read

这题如题主要是学习如何利用Angr实现内存地址的任意读，和CTF中的PWN题很像，这里的例子也都是很简单的漏洞利用

首先检测一下文件：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 15_angr_arbitrary_read
[*] '/home/syc/Desktop/TEMP/15_angr_arbitrary_read'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

我们用IDA打开这个文件，看一看函数：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+Ch] [ebp-1Ch]
  char *s; // [esp+1Ch] [ebp-Ch]

  s = try_again;
  print_msg();
  printf("Enter the password: ");
  __isoc99_scanf("%u %20s", &key, &v4);
  if ( key == 19511649 )
    puts(s);
  else
    puts(try_again);
  return 0;
}
```

刚开始拿到这题我们是有点懵逼的，因为太简单了，不懂利用点在哪里，其实我们只要铭记所有题目的核心关键是输出“Godd Job”

我们看一下puts函数的用法

```c
int puts(const char *string);
```

传入的是一个字符串指针，我们所有题目的目标都是最后获得输出Good Job，这题单单看反汇编代码无法发现如何获得正确输出，回想一下标题任意读，我们可以发现这题的关键是修改s处内存的指针地址，然后搜索一下程序的字符串表

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200901091836.png)

发现程序中存在"Good Job."字符串验证了我们之前的想法，我们目前需要做的事情就是把s存储的地址修改为Good Job所在的地址即**0x594e4257**

那我们如何修改呢，视线回到充满着漏洞和内存泄漏的scanf函数，观察一下v4的栈结构

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200901092304.png)

可以发现v4和s在内存上是相邻的，且只相差20地址，回到scanf函数

```c
__isoc99_scanf("%u %20s", &key, &v4);
```

允许我们输入20个字符，存在越界写的问题，可输入的字符串刚刚好可以让我们覆盖到 `s`，这就给了我们可以修改s字符的机会

先上EXP，再逐步分析：

```python
import angr
import sys
import claripy
def Go():
    path_to_binary = "./15_angr_arbitrary_read" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 'A', char <= 'Z')
            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1)
            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    def check_puts(state):
        puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        if state.se.symbolic(puts_parameter):
            good_job_string_address = 0x594e4257
            is_vulnerable_expression = puts_parameter == good_job_string_address

            copied_state = state.copy()
            copied_state.add_constraints(is_vulnerable_expression)

            if copied_state.satisfiable():
                state.add_constraints(is_vulnerable_expression)
                return True
            else:
                return False
        else:
            return False
    
    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        puts_address = 0x8048370
        if state.addr == puts_address:
            return check_puts(state)
        else:
            return False
    
    simulation.explore(find=is_successful)

    if simulation.found:
        solution_state = simulation.found[0]
        (scanf0, scanf1) = solution_state.globals['solutions']
        solution0 = (solution_state.solver.eval(scanf0))
        solution1 = (solution_state.solver.eval(scanf1,cast_to=bytes))
        print("[+] Success! Solution is: {0} {1}".format(solution0, solution1))
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
```

运行一下验证结果：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/QQ%E5%9B%BE%E7%89%8720200901210631.png)

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200901210802.png)

现在开始解析脚本,一开始的时候同往常一样，angr可以自动处理

```python
path_to_binary = "./15_angr_arbitrary_read" 
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state()
```

接下来我们需要同之前几题一样Hook Scanf函数，为此我们需要自己编写一个替换函数，注意同之前的知识相结合

```python
class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)
            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 'A', char <= 'Z')
            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1)
            self.state.globals['solutions'] = (scanf0, scanf1)
```

因为第一个参数key是无符号整数，即占用8*4=32比特，第二个参数v4我们需要输入20个字符才能覆盖到s的地址，故总共需要20\*8个比特，我们这就完成了两个符号位向量的构建

```python
scanf0 = claripy.BVS('scanf0', 32)
scanf1 = claripy.BVS('scanf1', 20*8)
```

这题我们需要确保字符串中的每个字符都是可打印的，这就需要我们添加新的条件约束，即约束每个字节的范围在ASCII码中，同时因为一个字符是8比特，故我们需要将scanf1这个符号位向量按8比特一组切分为一个字节一个字节

```python
for char in scanf1.chop(bits=8):
	self.state.add_constraints(char >= 'A', char <= 'Z')
```

这里我们引入`project.arch.memory_endness`将符号位向量设置为小端序，并设置解集

```python
scanf0_address = param0
self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
scanf1_address = param1
self.state.memory.store(scanf1_address, scanf1)
self.state.globals['solutions'] = (scanf0, scanf1)
```

然后开始设置根据符号表函数名进行Hook操作

```python
scanf_symbol = '__isoc99_scanf'
project.hook_symbol(scanf_symbol, ReplacementScanf())
```

然后我们需要一个验证函数求证我们求解出的状态是正确的输出状态，所以需要编写一个check_puts函数进行检查，我们主要是在检查puts函数调用时传入的参数s的值，这里有一个独特的地方我们检查的puts地址是PLT地址，

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200901223730.png)

因为有两个地方都调用了puts函数，而puts是一个外部导入函数，每次调用本质上都需要访问PLT表，所以我们直接捕获运行到puts的PLT地址的state做检查就行

```python
def is_successful(state):
	puts_address = 0x8048370
	if state.addr == puts_address:
     	return check_puts(state)
    else:
		return False
```

接下来我们开始编写check函数，首先我们知道puts函数只有一个参数，那这个参数一定是存在栈上esp指针+4的位置（具体可以去参阅32位Linux函数传参格式）

```
esp + 7 -> /----------------\
esp + 6 -> |      puts      |
esp + 5 -> |    parameter   |
esp + 4 -> \----------------/
esp + 3 -> /----------------\
esp + 2 -> |     return     |
esp + 1 -> |     address    |
    esp -> \----------------/
```

我们调用memory的load方法将这个数据提取出来看看是不是goodjob字符串所在的地址

```python
def check_puts(state):
	puts_parameter = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
	if state.se.symbolic(puts_parameter):
		good_job_string_address = 0x594e4257
        is_vulnerable_expression = puts_parameter == good_job_string_address
```

这里我们需要对当前状态做一个拷贝，方便操作状态而不对原来的状态产生影响干扰，然后给状态添加约束条件，如果地址相等则返回正确

```python
copied_state = state.copy()
            copied_state.add_constraints(is_vulnerable_expression)

            if copied_state.satisfiable():
                state.add_constraints(is_vulnerable_expression)
                return True
            else:
                return False
        else:
            return False
```

接下来的部分都是大同小异，不再赘述

## 16_angr_arbitrary_write

这题如题就是学习如何任意写，老样子先检查一下文件

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 16_angr_arbitrary_write
[*] '/home/syc/Desktop/TEMP/16_angr_arbitrary_write'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用IDA打开检查一下函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+Ch] [ebp-1Ch]
  char *dest; // [esp+1Ch] [ebp-Ch]

  dest = unimportant_buffer;
  memset(&s, 0, 0x10u);
  strncpy(password_buffer, "PASSWORD", 0xCu);
  print_msg();
  printf("Enter the password: ");
  __isoc99_scanf("%u %20s", &key, &s);
  if ( key == 24173502 )
    strncpy(dest, &s, 0x10u);
  else
    strncpy(unimportant_buffer, &s, 0x10u);
  if ( !strncmp(password_buffer, "DVTBOGZL", 8u) )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

一开始也是毫无头绪，记得我们之前铭记的做题核心就是输出“Good Job."，顺着这个思路往上走，第一步我们观察

```c
!strncmp(password_buffer, "NDYNWEUJ", 8u)
```

需要的条件是`password_buffer`的里面内容为`NDYNWEUJ`，接下来的问题是如何指定内容，我们发现并没有直接的渠道给我们去修改这里的内容，我们思路到哪些渠道可以提供给我们修改内存内容值，可以得知：

```c
dest = unimportant_buffer;
__isoc99_scanf("%u %20s", &key, &s);
strncpy(dest, &s, 0x10u);
strncpy(unimportant_buffer, &s, 0x10u);
```

我们回顾一下`strncpy`函数：

```c
char *strncpy(char *dest, const char *src, int n)
```

表示把`src`所指向的字符串中以`src`地址开始的前n个字节复制到`dest`所指的数组中，并返回被复制后的`dest`

```c
strncmp(password_buffer, "DVTBOGZL", 8u)
```

可以想到我们可以将`dest`指向`password_buffer`，然后将`src`的内容修改为`DVTBOGZL`即可，然后我们知道一开始`dest`已经指向`unimportant_buffer`，我们如何修改`dest`呢？

回忆起上一题的手法，观察这个函数：

```c
__isoc99_scanf("%u %20s", &key, &s);
```

```c
-0000001C s               db ?
-0000001B                 db ? ; undefined
-0000001A                 db ? ; undefined
-00000019                 db ? ; undefined
-00000018                 db ? ; undefined
-00000017                 db ? ; undefined
-00000016                 db ? ; undefined
-00000015                 db ? ; undefined
-00000014                 db ? ; undefined
-00000013                 db ? ; undefined
-00000012                 db ? ; undefined
-00000011                 db ? ; undefined
-00000010                 db ? ; undefined
-0000000F                 db ? ; undefined
-0000000E                 db ? ; undefined
-0000000D                 db ? ; undefined
-0000000C dest            dd ?                    ; offset
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
```

`s`和`dest`刚好只相差16字节，完全覆盖`dest`刚好需要20个字节，而`scanf`函数刚好给我们提供了20个字节，这里用上一题差不多的手法就行，当我们控制了dest的地址后，s的前16个字节又是我们可控的，于是我们就实现了任意地址写的功能

老样子先上EXP：

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./16_angr_arbitrary_write"
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)

            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 48, char <= 96)

            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1)

            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf' 
    project.hook_symbol(scanf_symbol, ReplacementScanf())

  
    def check_strncpy(state):
        strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
        strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
        strncpy_len = state.memory.load(state.regs.esp + 12, 4, endness=project.arch.memory_endness)

        src_contents = state.memory.load(strncpy_src, strncpy_len)

        if state.solver.symbolic(src_contents) and state.solver.symbolic(strncpy_dest):
            password_string = 'DVTBOGZL' 
            buffer_address = 0x4655544c 

            does_src_hold_password = src_contents[-1:-64] == password_string
            does_dest_equal_buffer_address = strncpy_dest == buffer_address

            if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
                state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
                return True
            else:
                return False
        else: 
                return False

    simulation = project.factory.simgr(initial_state)

    def is_successful(state):
        strncpy_address = 0x8048410
        if state.addr == strncpy_address:
            return check_strncpy(state)
        else:
            return False

    simulation.explore(find=is_successful)

    if simulation.found:
        solution_state = simulation.found[0]

        scanf0, scanf1 = solution_state.globals['solutions']
        solution0 = (solution_state.solver.eval(scanf0))
        solution1 = (solution_state.solver.eval(scanf1,cast_to=bytes))
        print("[+] Success! Solution is: {0} {1}".format(solution0, solution1))
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    Go()
```

运行一下查看结果：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/QQ%E5%9B%BE%E7%89%8720200903172213.png)

接下来我们来分析一下脚本：

一开始的脚本和上一题都没有什么太大的区别，也是在hook我们的scanf函数然后做条件约束为可见字符之类的

```python
def Go():
    path_to_binary = "./16_angr_arbitrary_write"
    project = angr.Project(path_to_binary)

    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 20*8)

            for char in scanf1.chop(bits=8):
                self.state.add_constraints(char >= 48, char <= 96)

            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1)

            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf' 
    project.hook_symbol(scanf_symbol, ReplacementScanf())
```

这里我们从检查`puts`函数变为了检查`strncpy`函数，我们需要检查的是`strncpy`的`dest`参数是否已经修改为`password_buffer`，且`src`参数是否为密码字符串，这里需要注意的是此时的参数栈结构：

```
esp + 7 -> /----------------\
esp + 6 -> |      puts      |
esp + 5 -> |    parameter   |
esp + 4 -> \----------------/
esp + 3 -> /----------------\
esp + 2 -> |     return     |
esp + 1 -> |     address    |
    esp -> \----------------/
```

我们利用memory的load方法把参数内容提取出来

```python
def check_strncpy(state):
	strncpy_src = state.memory.load(state.regs.esp + 8, 4, endness=project.arch.memory_endness)
	strncpy_dest = state.memory.load(state.regs.esp + 4, 4, endness=project.arch.memory_endness)
	strncpy_len = state.memory.load(state.regs.esp + 12, 4, endness=project.arch.memory_endness)
```

这里需要注意的是我们在检查src参数是否正确的时候需要的是里面的字符串内容，然而我们第一次获取的是`src`字符串的地址，我们还需要再调用一次load方法把src真正的内容提取出来

```python
src_contents = state.memory.load(strncpy_src, strncpy_len)
```

然后就是正常的参数验证环节，首先验证src字符串是否为我们想要的字符串，因为机器是小端序，所以我们需要`[-1:-64]`这样来比较

```python
if state.solver.symbolic(src_contents) and state.solver.symbolic(strncpy_dest):
            password_string = 'DVTBOGZL' 
            buffer_address = 0x4655544c 

            does_src_hold_password = src_contents[-1:-64] == password_string
            does_dest_equal_buffer_address = strncpy_dest == buffer_address
```

当`src`字符串的确为我们需要的时候，接下来判定`dest`是否为`password_buffe`的地址

```python
if state.satisfiable(extra_constraints=(does_src_hold_password, does_dest_equal_buffer_address)):
	state.add_constraints(does_src_hold_password, does_dest_equal_buffer_address)
	return True
else:
	return False
```

接下来都是比较常规的套路了，不再赘述

## 17_angr_arbitrary_jump

如题目所示，这题主要是学会任意地址跳转，即利用Angr处理无约束状态，老样子先检查一下文件：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 17_angr_arbitrary_jump
[*] '/home/syc/Desktop/TEMP/17_angr_arbitrary_jump'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

然后用IDA打开检查一下函数

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  print_msg();
  printf("Enter the password: ");
  read_input();
  puts("Try again.");
  return 0;
}
```

```c
int print_msg()
{
  return printf("%s", msg);
}
```

```c
int read_input()
{
  char v1; // [esp+1Ah] [ebp-1Eh]

  return __isoc99_scanf("%s", &v1);
}
```

然后我们还可以发现存在一个没有被调用到的函数`print_good`

```c
void __noreturn print_good()
{
  puts("Good Job.");
  exit(0);
}
```

我们不难发现这题里面的read_input()函数里的scanf存在栈溢出漏洞，简单来说这题就是非常简单的ROP使得我们跳转到print_good函数

话不多说先上EXP：

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./17_angr_arbitrary_jump" 
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state() 
     
    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, input_buffer_address):
            input_buffer = claripy.BVS(
                'input_buffer', 64 * 8)  
            for char in input_buffer.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            self.state.memory.store(
                input_buffer_address, input_buffer, endness=project.arch.memory_endness)
            self.state.globals['solution'] = input_buffer

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    simulation = project.factory.simgr(
        initial_state, 
        save_unconstrained=True,
        stashes={
        'active' : [initial_state],
        'unconstrained' : [],
        'found' : [],
        'not_needed' : []
        }
    )

    def check_vulnerable(state):
        return state.solver.symbolic(state.regs.eip)

    def has_found_solution():
        return simulation.found

    def has_unconstrained_to_check():
        return simulation.unconstrained

    def has_active():
        return simulation.active

    while (has_active() or has_unconstrained_to_check()) and (not has_found_solution()):
        for unconstrained_state in simulation.unconstrained:
            def should_move(s):
                return s is unconstrained_state
            simulation.move('unconstrained', 'found', filter_func=should_move)
        simulation.step()

    if simulation.found:
        solution_state = simulation.found[0]
        solution_state.add_constraints(solution_state.regs.eip == 0x4d4c4749)
        solution = solution_state.solver.eval(
        solution_state.globals['solution'], cast_to=bytes)
        print(solution[::-1])
    else:
        raise Exception('Could not find the solution')

if __name__ == '__main__':
    Go()
```

运行一下验证结果：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E5%9B%9B/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200903220756.png)

下面开始逐步讲解EXP

当一条指令有太多可能的分支时，就会出现无约束状态。当指令指针完全是符号指针时，就会发生这种情况，这意味着用户输入可以控制计算机执行的代码的地址

```assembly
mov user_input, eax
jmp eax
```

例如此题存在的栈溢出漏洞就可以让我们的程序进入无约束状态。一般情况下，当Angr遇到不受约束的状态时，它会将其抛出。在我们的例子中，我们希望利用无约束状态来跳转到我们选择的位置。我们将在稍后了解如何禁用Angr的默认行为

一开始的情况都是一样的

```python
def Go():
    path_to_binary = "./17_angr_arbitrary_jump" 
    project = angr.Project(path_to_binary)
    initial_state = project.factory.entry_state() 
```

然后老样子Hook掉我们的scanf函数，使得输入的信息都是可见字符串

```python
class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, input_buffer_address):
            input_buffer = claripy.BVS(
                'input_buffer', 64 * 8)  
            for char in input_buffer.chop(bits=8):
                self.state.add_constraints(char >= '0', char <= 'z')

            self.state.memory.store(
                input_buffer_address, input_buffer, endness=project.arch.memory_endness)
            self.state.globals['solution'] = input_buffer

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())
```

然后我们将改变Angr的模拟引擎的默认设置，参数`save_unconstrained=True`时指定Angr不抛出不受约束的状态。相反，它会将它们移动到名为`simul.com unconstrained`的stashes 中。此外，我们将使用一些默认情况下不包含的stashes ，如'found'和'not_needed'。稍后将学习如何使用它们

- active：程序仍能进一步执行
- deadended：程序结束
- errored：Angr执行中出现错误的状态
- unconstrained：不受约束的状态
- found：找到路径答案的状态
- not_needed：所有其它情况

```python
simulation = project.factory.simgr(
        initial_state, 
        save_unconstrained=True,
        stashes={
        'active' : [initial_state],
        'unconstrained' : [],
        'found' : [],
        'not_needed' : []
        }
    )
```

接下来我们将定义四个函数来获得我们想要获得的程序状态

```python
#检查无约束状态是否可利用
def check_vulnerable(state):
	return state.solver.symbolic(state.regs.eip)

def has_found_solution():
	return simulation.found
#检查是否还有未受约束的状态需要检查
def has_unconstrained_to_check():
	return simulation.unconstrained
#active是可以进一步探索的所有状态的列表
def has_active():
	return simulation.active
```

我们之前一直使用的`simulation.explore`方法并不适合我们现在这种情况，因为`find`参数指定的方法不会在无约束状态下被调用，想要自己探索未约束情况下的二进制代码，我们需要自己编写解决方案

```python
while (has_active() or has_unconstrained_to_check()) and (not has_found_solution()):
        for unconstrained_state in simulation.unconstrained:
            def should_move(s):
                return s is unconstrained_state
            simulation.move('unconstrained', 'found', filter_func=should_move)
        simulation.step()
```

上面这个解决方案的思路是，因为我们需要的是无约束状态，如果出现了约束状态下的解则求解失败，故有`and (not has_found_solution())`，且有待检查的状态才继续循环遍历所有的状态。最终的结果是找到了一个未约束状态

接下来的代码和之前的大同小异，就不再赘述

> Tips：出现一些奇怪的问题，建议参考一下官方关于Angr在改用Python3之后的一些API变化：
>
> Migrating to angr 8 —— https://docs.angr.io/appendix/migration#deprecations-and-name-changes

## 参考文献

【1】angr官方文档—— https://docs.angr.io/core-concepts

【2】angr 系列教程(一）核心概念及模块解读—— https://xz.aliyun.com/t/7117#toc-14

【3】Enhancing Symbolic Execution with Veritesting —— Carnegie Mellon University

【4】angr 文档翻译(1-2):加载一个二进制文件——CLE和angr工程 —— https://www.jianshu.com/p/f660800bb70f


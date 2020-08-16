# Angr_CTF从入门到精通（三）

PS：因为最近开始考试，耽误了很多时间，重新开始恢复

在之前的学习中我们学会了利用angr符号化寄存器、栈上的值、内存、malloc开辟的动态内存和文件系统，感受到了angr强大的仿真系统，在CTF中题目的简单利用，接下来我们要学习angr的更多的高级用法

> 由于angr的api一直有一些变化，网上的很多脚本需要修改才能运行

## 08_angr_constraints

该题主要学习通过添加约束条件来解决路径爆炸问题

首先检查一下该程序：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 08_angr_constraints
[*] '/home/syc/Desktop/TEMP/08_angr_constraints'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

然后进入IDA查看该：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [esp+Ch] [ebp-Ch]

  password = 1146115393;
  dword_804A044 = 1380994638;
  dword_804A048 = 1381647695;
  dword_804A04C = 1112233802;
  memset(&buffer, 0, 0x11u);
  printf("Enter the password: ");
  __isoc99_scanf("%16s", &buffer);
  for ( i = 0; i <= 15; ++i )
    *(_BYTE *)(i + 0x804A050) = complex_function(*(char *)(i + 0x804A050), 15 - i);
  if ( check_equals_AUPDNNPROEZRJWKB(&buffer, 16) )
    puts("Good Job.");
  else
    puts("Try again.");
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
  return (a1 - 65 + 53 * a2) % 26 + 65;
}
```

```c
_BOOL4 __cdecl check_equals_AUPDNNPROEZRJWKB(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(_BYTE *)(i + a1) == *(_BYTE *)(i + 0x804A040) )
      ++v3;
  }
  return v3 == a2;
}
```

### 路径爆炸

通过我们之前的学习体验感觉到angr这么强大的应用怎么没有在实际的测试生产中大规模应用，这是因为给符号执行技术在复杂程序的测试案例生成的应用中造成阻碍的两个大问题：一个是约束求解问题，另一个就是路径爆炸问题

所谓符号执行就是把程序中的变量符号化去模拟程序运行，搜集路径约束条件并使用约束求解器对其进行求解后得到结果。当一个程序存在循环结构时，即使逻辑十分简单也可能会产生规模十分巨大的执行路径。在符号执行的过程中，每个分支点都会产生两个实例，当程序中存在循环结构展开时，可能会导致程序分支路径数呈指数级增长，即路径爆炸问题。故我们需要提供更多的约束条件控制路径爆照问题

回到这个题目本身

```c
_BOOL4 __cdecl check_equals_AUPDNNPROEZRJWKB(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(_BYTE *)(i + a1) == *(_BYTE *)(i + 0x804A040) )
      ++v3;
  }
  return v3 == a2;
}
```

`check_equals_AUPDNNPROEZRJWKB()`函数就是一个字符一个字符的比较，就会产生路径爆炸问题，原始也是每次调用循环中的if语句（16次）时，计算机都需要产生判断分支，从而导致2 ^ 16 = 65,536分支，这将花费很长时间来测试并获得我们的答案。我们解决这个问题的答案，直接用约束条件取代这个判断函数，用字符串直接比较约束，从而避免因为循环和判断语句逐一字符比较而产生分支引起路径爆炸问题

### 约束求解

在angr中提供了可以用加入一个约束条件到一个state中的方法（`state.solver.add`），将每一个符号化的布尔值作为一个关于符号变量合法性的断言。之后可以通过使用`state.solver.eval(symbol)`对各个断言进行评测来求出一个合法的符号值（若有多个合法值，返回其中的一个）。简单来说就是通过 `.add` 对 state 对象添加约束，并使用 `.eval` 接口求解，得到符号变量的可行解

例如：

```python
# fresh state
>>> state = proj.factory.entry_state()
>>> state.solver.add(x - y >= 4)
>>> state.solver.add(y > 0)
>>> state.solver.eval(x)
5
>>> state.solver.eval(y)
1
>>> state.solver.eval(x + y)
6
```

总而言之先放EXP，再逐步分析：

```python
import angr
import sys
import claripy
def Go():
    path_to_binary = "./08_angr_constraints" 
    project = angr.Project(path_to_binary, auto_load_libs=False)

    start_address = 0x8048625
    buff_addr = 0x0804A050
    address_to_check_constraint = 0x08048565

    initial_state = project.factory.blank_state(addr=start_address)
   
    char_size_in_bits = 8
    passwd_len = 16
    passwd0 = claripy.BVS('passwd0', char_size_in_bits*passwd_len)
    initial_state.memory.store(buff_addr, passwd0)

    simulation = project.factory.simgr(initial_state)
    simulation.explore(find=address_to_check_constraint)

    if simulation.found:
        solution_state = simulation.found[0]
        constrained_parameter_address = buff_addr
        constrained_parameter_size_bytes = 16
        constrained_parameter_bitvector = solution_state.memory.load(
        constrained_parameter_address,
        constrained_parameter_size_bytes
    )
        constrained_parameter_desired_value = 'AUPDNNPROEZRJWKB'
        solution_state.solver.add(constrained_parameter_bitvector == constrained_parameter_desired_value)
        solution0 = solution_state.solver.eval(passwd0,cast_to=bytes)       
        print("[+] Success! Solution is: {0}".format(solution0))
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()
```

运行一下测试：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200810161941.png)

```assembly
.text:080485C4                 mov     ds:password, 'DPUA'
.text:080485CE                 mov     ds:dword_804A044, 'RPNN'
.text:080485D8                 mov     ds:dword_804A048, 'RZEO'
.text:080485E2                 mov     ds:dword_804A04C, 'BKWJ'
```

通过这里不难的得出需要比较的字符串是**AUPDNNPROEZRJWKB**（虽然从函数名也能看出来，但是还是从汇编解释一下为好）

首先总结一下我们的思路：

- 用户输入的字符串存储在buffer，buffer的地址为：0x804A050
- 比较函数`check_equals_AUPDNNPROEZRJWKB`的地址为：0x08048565
- 其实只要当程序运行到地址0x08048565时，处于buffer地址内的字符串等于AUPDNNPROEZRJWKB即可
- 添加上述约束条件即可一步得出结果，而不用进入比较函数逐一字符比较而产生路径爆炸问题

故一开始先填入需要利用到的地址：

```python
path_to_binary = "./08_angr_constraints" 
project = angr.Project(path_to_binary, auto_load_libs=False)
start_address = 0x8048625
buff_addr = 0x0804A050
address_to_check_constraint = 0x08048565
initial_state = project.factory.blank_state(addr=start_address)
```

因为输入是`scanf("%16s", &buffer);`，如之前一样，不难得出我们需要构建的符号位向量的参数

```python
char_size_in_bits = 8
passwd_len = 16
passwd0 = claripy.BVS('passwd0', char_size_in_bits*passwd_len)
initial_state.memory.store(buff_addr, passwd0)
```

然后初始化并执行模拟管理器，运行到调用check函数的状态

```python
simulation = project.factory.simgr(initial_state)
simulation.explore(find=address_to_check_constraint)
```

然后利用使用 `state.memory`  的  `.load(addr, size)`接口读出`buffer`处的内存数据

```python
if simulation.found:
	solution_state = simulation.found[0]
	constrained_parameter_address = buff_addr
	constrained_parameter_size_bytes = 16
	constrained_parameter_bitvector = solution_state.memory.load(
	constrained_parameter_address,
	constrained_parameter_size_bytes
)
```

利用slover求解引擎提供的add方法加入约束条件

```python
constrained_parameter_desired_value = 'AUPDNNPROEZRJWKB'
solution_state.solver.add(constrained_parameter_bitvector == constrained_parameter_desired_value)
```

接下来和之前的题目类似，不再赘述

## 09_angr_hooks

这题如题目所言，主要就是学习使用angr的hook技术解决路径爆炸问题，与我们之前利用的约束条件不同，hook技术则更为强大

> 以下内容来自维基百科：
>
> **钩子编程**（hooking），也称作“挂钩”，是计算机程序设计术语，指通过拦截软件模块间的函数调用、消息传递、事件传递来修改或扩展操作系统、应用程序或其他软件组件的行为的各种技术。处理被拦截的函数调用、事件、消息的代码，被称为**钩子**（hook）。
>
> 简单来说就是用我们自己设计的函数去取代被hook的函数

首先检查一下该程序：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 09_angr_hooks
[*] '/home/syc/Desktop/TEMP/09_angr_hooks'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用IDA查看一下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BOOL4 v3; // eax
  signed int i; // [esp+8h] [ebp-10h]
  signed int j; // [esp+Ch] [ebp-Ch]

  qmemcpy(password, "XYMKBKUHNIQYNQXE", 16);
  memset(buffer, 0, 0x11u);
  printf("Enter the password: ");
  __isoc99_scanf("%16s", buffer);
  for ( i = 0; i <= 15; ++i )
    *(_BYTE *)(i + 0x804A054) = complex_function(*(char *)(i + 0x804A054), 18 - i);
  equals = check_equals_XYMKBKUHNIQYNQXE(buffer, 16);
  for ( j = 0; j <= 15; ++j )
    *(_BYTE *)(j + 0x804A044) = complex_function(*(char *)(j + 0x804A044), j + 9);
  __isoc99_scanf("%16s", buffer);
  v3 = equals && !strncmp(buffer, password, 0x10u);
  equals = v3;
  if ( v3 )
    puts("Good Job.");
  else
    puts("Try again.");
  return 0;
}
```

```c
_BOOL4 __cdecl check_equals_XYMKBKUHNIQYNQXE(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(_BYTE *)(i + a1) == *(_BYTE *)(i + 0x804A044) )
      ++v3;
  }
  return v3 == a2;
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
  return (a1 - 65 + 23 * a2) % 26 + 65;
}
```

其实和上一题并没有什么太大的变化，主要是我们上一题是使用增加条件约束的方法减少路径分支，而这一题我们直接利用hook改写`complex_function`函数为我们自己的函数

### Hook

angr使用一系列引擎（SimEngine的子类）来模拟被执行代码对输入状态产生的影响。其中就有`hook engine`来处理hook的情况。默认情况下，angr 会使用 `SimProcedures` 中的符号摘要替换库函数，即设置 Hooking，这些 python 函数摘要高效地模拟库函数对状态的影响。可以通过 `angr.procedures`或 `angr.SimProcedures`  查看列表

`SimProcedure`  其实就是 Hook 机制，可以通过 `proj.hook(addr,hook)` 设置，其中 hook 是一个 `SimProcedure` 实例。 通过 `.is_hooked / .unhook / .hook_by` 进行管理。将 `proj.hook(addr)` 作为函数装饰器，可以编写自己的 hook 函数。还可以通过  `proj.hook_symbol(name,hook)` hook 函数

一个简单的例子：

```python
>>> @project.hook(0x1234, length=5)
... def set_rax(state):
...     state.regs.rax = 1
```

其中第一个参数即需要Hook的调用函数的地址，第二个参数`length`即指定执行引擎在完成挂钩后应跳过多少字节。具体多少字节由Hook处地址的指令长度确定，例如本题：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200811210031.png)

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200811210154.png)

我们需要Hook地址的机器指令长度为5个字节，故最后的hook函数：

```python
@project.hook(0x80486B3, length=5)
```

老样子先放最后EXP，再逐一分析：

```python
import angr
import sys
import claripy
def Go():
    path_to_binary = "./09_angr_hooks" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    check_equals_called_address = 0x80486B3
    instruction_to_skip_length = 5

    @project.hook(check_equals_called_address, length=instruction_to_skip_length)
    def skip_check_equals_(state):
        user_input_buffer_address = 0x804A054 
        user_input_buffer_length = 16

        user_input_string = state.memory.load(
            user_input_buffer_address,
            user_input_buffer_length
        )

        check_against_string = 'XKSPZSJKJYQCQXZV'

        register_size_bit = 32
        state.regs.eax = claripy.If(
            user_input_string == check_against_string, 
            claripy.BVV(1, register_size_bit), 
            claripy.BVV(0, register_size_bit)
        )

    simulation = project.factory.simgr(initial_state)

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
            print("[+] Success! Solution is: {0}".format(solution.decode('utf-8')))
            #print(solution0)
    else:
        raise Exception('Could not find the solution')
    
if __name__ == "__main__":
    Go()
```

运行一下查看结果：

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200811220414.png)

下面来逐步分析：

由于Angr可以处理对scanf的初始调用，因此我们可以从头开始

```python
path_to_binary = "./09_angr_hooks" 
project = angr.Project(path_to_binary, auto_load_libs=False)
initial_state = project.factory.entry_state()
```

如之前分析的而言，首先找到需要Hook的函数地址`0x080486B3`，然后设定指令长度

```python
check_equals_called_address = 0x80486B3
instruction_to_skip_length = 5
```

然后我们需要在在`@project.hook`语句之后书写我们的模拟函数。然后如上题一致，我们利用使用 `state.memory`  的  `.load(addr, size)`接口读出`buffer`处的内存数据，与答案进行比较

```python
@project.hook(check_equals_called_address, length=instruction_to_skip_length)
    def skip_check_equals_(state):
        user_input_buffer_address = 0x804A054 
        user_input_buffer_length = 16

        user_input_string = state.memory.load(
            user_input_buffer_address,
            user_input_buffer_length
        )

        check_against_string = 'XKSPZSJKJYQCQXZV'
```

然后这里的关键是，我们模拟一个函数就是把它视作一个黑盒，能成功模拟输入相对应的输出即可，所以我们需要处理check函数的返回值

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200811221326.png)

不难发现这个函数是利用EAX寄存器作为返回值，然后成功则返回1，不成功则返回0，还需要注意在构建符号位向量的时候EAX寄存器是32位寄存器

```python
register_size_bit = 32
        state.regs.eax = claripy.If(
            user_input_string == check_against_string, 
            claripy.BVV(1, register_size_bit), 
            claripy.BVV(0, register_size_bit)
        )
```

接下来同之前差不多，不再赘述

## 10_angr_simprocedures

这题主要学习如何利用函数名进行hook，而不是复杂的利用函数的调用地址

首先检查一下程序：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 10_angr_simprocedures
[*] '/home/syc/Desktop/TEMP/10_angr_simprocedures'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

用IDA打开看一下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  signed int i; // [esp+20h] [ebp-28h]
  char s[17]; // [esp+2Bh] [ebp-1Dh]
  unsigned int v6; // [esp+3Ch] [ebp-Ch]

  v6 = __readgsdword(0x14u);
  memcpy(&password, "ORSDDWXHZURJRBDH", 0x10u);
  memset(s, 0, 0x11u);
  printf("Enter the password: ");
  __isoc99_scanf("%16s", s);
  for ( i = 0; i <= 15; ++i )
    s[i] = complex_function(s[i], 18 - i);
  if ( check_equals_ORSDDWXHZURJRBDH(s, 16) )
    puts("Good Job.");
  else
    puts("Try again.");
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
  return (a1 - 65 + 29 * a2) % 26 + 65;
}
```

```c
_BOOL4 __cdecl check_equals_ORSDDWXHZURJRBDH(int a1, unsigned int a2)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < a2; ++i )
  {
    if ( *(_BYTE *)(i + a1) == *(_BYTE *)(i + 0x804C048) )
      ++v3;
  }
  return v3 == a2;
}
```

这一题与上一题相似， 我们必须替换check_equals函数 。但是，我们可以发现check_equals被调用了很多次，以致于无法通过地址Hook每个调用位置。 这时我们必须使用SimProcedure编写我们自己的check_equals实现，然后通过函数名Hook所有对`check_equals`的调用

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E6%88%AA%E5%9B%BE_20200812220216.png)

### Hooking Symbols

每一个程序都有一个符号表，angr可以确保从每个导入符号都可以解析出地址，可以使用angr提供的`Project.hook_symbol`API来通过符号名来Hook函数所有的调用地址，这意味着可以用自己的代码替换函数，一个简单的例子：

```python
>>> class NotVeryRand(SimProcedure):
...     def run(self, return_values=None):
...         rand_idx = self.state.globals.get('rand_idx', 0) % len(return_values)
...         out = return_values[rand_idx]
...         self.state.globals['rand_idx'] = rand_idx + 1
...         return out

>>> project.hook_symbol('rand', NotVeryRand(return_values=[413, 612, 1025, 1111]))
```

老样子别说话，上EXP：

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./10_angr_simprocedures" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class ReplacementCheckEquals(angr.SimProcedure):
        def run(self, to_check, length):
            user_input_buffer_address = to_check
            user_input_buffer_length = length
            user_input_string = self.state.memory.load(
                user_input_buffer_address,
                user_input_buffer_length
            )
            check_against_string = 'ORSDDWXHZURJRBDH'
            return claripy.If(
                user_input_string == check_against_string, 
                claripy.BVV(1, 32), 
                claripy.BVV(0, 32)
            )
    
    check_equals_symbol = 'check_equals_ORSDDWXHZURJRBDH'
    project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())

    simulation = project.factory.simgr(initial_state)

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
            print("[+] Success! Solution is: {0}".format(solution.decode('utf-8')))
            #print(solution0)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
```

运行一下查看结果

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200816163605.png)

这里前面的部分都可以直接照抄上面一题的代码，关键是定义一个继承angr.SimProcedure的类，以利用Angr的SimProcedures。

```python
class ReplacementCheckEquals(angr.SimProcedure):
```

SimProcedure用Python编写的我们自己的函数代替了原来函数。 除了用Python编写之外，该函数的行为与用C编写的任何函数基本相同。`self`之后的任何参数都将被视为要替换的函数的参数， 参数将是符号位向量。 另外，Python可以以常用的Python方式返回，Angr将以与原来函数相同的方式对待它

我们先来看一下函数原型：

```c
_BOOL4 __cdecl check_equals_ORSDDWXHZURJRBDH(char *to_check, unsigned int length)
{
  int v3; // [esp+8h] [ebp-8h]
  unsigned int i; // [esp+Ch] [ebp-4h]

  v3 = 0;
  for ( i = 0; i < length; ++i )
  {
    if ( to_check[i] == *(_BYTE *)(i + 0x804C048) )
      ++v3;
  }
  return v3 == length;
}
```

不难发现函数的第一个参数是待检测字符串首地址指针，然后就是字符串的长度，接下来我们就可以开始书写我们的模拟函数

```python
def run(self, to_check, length):
    		#即第一个参数
            user_input_buffer_address = to_check
            #即第二个参数
            user_input_buffer_length = length
			#使用self.state在SimProcedure中查找系统状态，从该状态的内存中提取出数据
            user_input_string = self.state.memory.load(
                user_input_buffer_address,
                user_input_buffer_length
            )
            check_against_string = 'ORSDDWXHZURJRBDH'
            #如果符合条件则返回输入的符号位向量
            return claripy.If(
                user_input_string == check_against_string, 
                claripy.BVV(1, 32), 
                claripy.BVV(0, 32)
            )
```

Hook上check_equals函数， angr会自动查找与该函数符号关联的地址

```python
check_equals_symbol = 'check_equals_WQNDNKKWAWOLXBAC' 
project.hook_symbol(check_equals_symbol, ReplacementCheckEquals())
```

 之后的操作与其他题目类似，不再赘述

## 11_angr_sim_scanf

如题，这题主要是学习如何hook`scanf`函数，步骤其实与上一题是几乎一致的，得先找到需要hook的函数符号，然后编写一个继承angr.SimProcedure的类，然后利用`hook_symbol`对函数进行hook

首先检测一下程序：

```bash
syc@ubuntu:~/Desktop/TEMP$ checksec 11_angr_sim_scanf
[*] '/home/syc/Desktop/TEMP/11_angr_sim_scanf'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

打开IDA查看一下程序：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _BOOL4 v3; // eax
  int i; // [esp+20h] [ebp-28h]
  char s[4]; // [esp+28h] [ebp-20h]
  int v7; // [esp+2Ch] [ebp-1Ch]
  unsigned int v8; // [esp+3Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  print_msg();
  memset(s, 0, 0x14u);
  qmemcpy(s, "DCLUESMR", 8);
  for ( i = 0; i <= 7; ++i )
    s[i] = complex_function(s[i], i);
  printf("Enter the password: ");
  __isoc99_scanf("%u %u", buffer0, buffer1);
  v3 = !strncmp(buffer0, s, 4u) && !strncmp(buffer1, (const char *)&v7, 4u);
  if ( v3 )
    puts("Good Job.");
  else
    puts("Try again.");
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
  return (a1 - 65 + 29 * a2) % 26 + 65;
}
```

还记得之前我们有一题也是scanf函数的复杂格式化字符串处理吗？没错，就是`03_angr_simbolic_registers`，那一题我们是利用符号化寄存器实现了scanf函数的多参数处理。而在这一题中，我们采用的是Hook重写库函数`scnaf`实现复杂格式化字符串的支持

客官新鲜的二两EXP这就奉上

```python
import angr
import claripy
import sys

def Go():
    path_to_binary = "./11_angr_sim_scanf" 
    project = angr.Project(path_to_binary, auto_load_libs=False)
    initial_state = project.factory.entry_state()

    class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 32)

            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)

            self.state.globals['solutions'] = (scanf0, scanf1)

    scanf_symbol = '__isoc99_scanf'
    project.hook_symbol(scanf_symbol, ReplacementScanf())

    simulation = project.factory.simgr(initial_state)
    
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
            stored_solutions = solution_state.globals['solutions']
            scanf0_solution = solution_state.solver.eval(stored_solutions[0])
            scanf1_solution = solution_state.solver.eval(stored_solutions[1])
            print("[+] Success! Solution is: {0} {1}".format(scanf0_solution,scanf1_solution))
            #print(scanf0_solution, scanf1_solution)
    else:
        raise Exception('Could not find the solution')

if __name__ == "__main__":
    Go()
```

运行一下查看结果

![](https://note-book.obs.cn-east-3.myhuaweicloud.com/Angr_CTF/%E4%B8%89/%E5%BE%AE%E4%BF%A1%E5%9B%BE%E7%89%87_20200816220158.png)

之前的步骤很多都和上一题一样，只不过在编写模拟的scanf函数的时候有一些不太一样

```python
 class ReplacementScanf(angr.SimProcedure):
        def run(self, format_string, param0, param1):
            scanf0 = claripy.BVS('scanf0', 32)
            scanf1 = claripy.BVS('scanf1', 32)

            scanf0_address = param0
            self.state.memory.store(scanf0_address, scanf0, endness=project.arch.memory_endness)
            scanf1_address = param1
            self.state.memory.store(scanf1_address, scanf1, endness=project.arch.memory_endness)            
```

还记得之前在`05_angr_symbolic_memory`我们学会的如何符号化内存吗？因为我们这里Scanf是要向内存写入数据的，于是我们利用使用 `state.memory`  的  `.store(addr, val)`  接口将符号位向量写入两个字符串的内存区域

### globals

这里的关键我们都知道Python的变量生存周期，在这里`scanf0`和`scanf1`是函数`ReplacementScanf`的局部变量，为了让函数外部也能获得我们输入的符号位向量，从而调用求解器获得答案，需要将这两个符号位向量变为全局变量，这里我们需要调用带有全局状态的globals插件中“保存”对我们的符号值的引用。globals插件允许使用列表，元组或多个键的字典来存储多个位向量

```python
self.state.globals['solutions'] = (scanf0, scanf1)
```

 之后的操作与其他题目类似，不再赘述

## 参考文献

【1】angr官方文档—— https://docs.angr.io/core-concepts

【2】angr 系列教程(一）核心概念及模块解读—— https://xz.aliyun.com/t/7117#toc-14

【3】王田园. 符号执行的路径爆炸及约束求解问题研究[D].大连海事大学,2019.

【4】曹琰. 面向软件脆弱性分析的并行符号执行技术研究[D].解放军信息工程大学,2013.
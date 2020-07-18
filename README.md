# Fuzzer-of-Papers
the link of paper and source code, and an abstract of paper

1. [Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization](# Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization)
2. [MemLock: Memory Usage Guided Fuzzing](# MemLock: Memory Usage Guided Fuzzing)
3. [Sequence Coverage Directed Greybox Fuzzing](# Sequence Coverage Directed Greybox Fuzzing )

## Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization

### 摘要

- **解决的问题**：

大多数覆盖率指导的fuzzer无法区分不同边的”覆盖率“（对漏洞挖掘的贡献能力）

- **已有解决方案**：

当前基于覆盖率的模糊测试工具同等对待所覆盖的代码。不管是普通语句或跳转语句以及对安全性有多大影响，所有触发新edge的输入都将保留以备将来进行变异。从提升代码覆盖率的角度对软件进行测试来看，此设计是合理的，但是1）当前技术仍不足以在合理的时间内达到完全的代码覆盖，因此漏洞挖掘效率低；2）我们希望尽快的发现漏洞，以便及时修复。同时，由于对各种代码覆盖率标准无差别对待，当前的模糊测试工具在面临施加了anti-fuzzing 技术的程序时，漏洞挖掘的效率大大降低。

- **本文提出的创新方案概述**：

为了解决无差别对待覆盖率衡量标准的限制，本文提出了一种基于安全影响来评估覆盖率的新方法。从三个不同角度来进行评估：函数、循环、基本块。基于提出的度量标准，设计并实现一种新的方案 TortoiseFuzz 来对模糊测试中的输入进行优先排序，用于挖掘内存损坏漏洞，还可以对抗 anti-fuzzing 技术。

- **实验效果**：

对30个真实程序进行了实验，并将其与6种最新的灰盒和混合模糊测试工具进行了比较：AFL，AFLFast，FairFuzz，MOPT，QSYM和Angora。据统计，TortoiseFuzz发现的漏洞比6个模糊测试工具（AFL，AFLFast，FairFuzz，MOPT和Angora）中的5个要多，其结果与QSYM相当，但平均仅消耗QSYM内存使用量的2％。此外，我们将本文的覆盖率衡量指标应用于QSYM，使其发现的漏洞数量平均增加28.6％。TortoiseFuzz发现了20个0 day漏洞，其中15个已获得CVE编号。

>1. paper：https://www.ndss-symposium.org/wp-content/uploads/2020/02/24422-paper.pdf
>2. slides：https://www.ndss-symposium.org/wp-content/uploads/24422-slides.pdf
>3. code：https://github.com/TortoiseFuzz/TortoiseFuzz
>4. video：https://www.youtube.com/watch?v=Fud0v0ppCOo&list=PLfUWWM-POgQtbJfU8PJRue_ZzASLfHF5Y&index=5&t=0s

## MemLock: Memory Usage Guided Fuzzing

## 摘要

- **解决的问题**：

挖掘内存消耗型漏洞

- **现状**：

对内存的滥用可能会导致严重的漏洞，如攻击者能控制输入来消耗大量的内存从而导致服务器拒绝服务。但是，目前很难检测此类型的漏洞，因为现有的大多数fuzz技术以覆盖率为目标，而不是挖掘内存消耗型漏洞。现有的灰盒测试技术并不能检测内存消耗型漏洞，因为这些漏洞不仅仅取决于程序的路径，也会取决于路径上一些特定的状态.

- **本文提出的创新方案概述**：

本文主要关注与三类内存内存消耗型漏洞：uncontrolled-recursion：当程序不能控制递归的次数时，可能会耗尽栈内存；uncontrolled-memory-allocation：程序使用不信任的size来分配内存，导致任意大小的内存被消耗；memory leak：若程序未跟踪、释放已被使用过的内存，可能会导致内存泄漏。在本文中，我们采用灰盒模糊测试技术来自动化的检测内存消耗错误。

**实验效果**：

我们在14个广泛使用的真实程序中对MemLock进行了全面的评估。 我们的实验结果表明，在发现内存消耗错误方面，MemLock大大优于包括AFL，AFLfast，PerfFuzz，FairFuzz，Angora和QSYM在内的最新的模糊测试技术。在实验过程中，我们发现了许多以前未知的内存消耗错误，并收到了15个新的CVE。

> 1. paper：https://wcventure.github.io/pdf/ICSE2020_MemLock.pdf
> 2. code：https://github.com/wcventure/MemLock-Fuzz
> 3. video：https://www.youtube.com/watch?v=yjqzaGnT5zk&feature=youtu.be

## Sequence Coverage Directed Greybox Fuzzing 

## 摘要

- **解决的问题**：导向性模糊测试的优化

  AFLGo 主要是为了达到目标程序中指定的代码位置，并且这些代码位置是相互独立的。为了减少运行时开销，AFLGo在插桩阶段静态的计算每个基本块到目标位置的距离。主要包括对CG、CFG的分析、每个基本块的距离计算。这使得AFLGo在运行时开销较低，因为距离信息已经计算得到。

  由于AFLGo的静态距离计算机制，导致两个严重的问题：

  1. 编译插桩阶段开销太大
  2. AFLGo对所有的基本块插桩，但是运行时仅会覆盖其中一部分；一旦重新制定目标代码，就得重新编译一遍

- **已有解决方案**：现有的导向性fuzz并不高效，导向性白盒fuzzer：BugRedux是基于符号执行实现的，花费很多时间在程序分析和运行时的约束求解。导向性灰盒fuzzer：AFLGo运行时开销较低，但是在插桩阶段进行了大量的计算。

- **本文提出的创新方案概述**：本文提出序列化覆盖率的导向性fuzzer：SCDF，一种轻量级的导向性fuzz技术，可以有效地探索用户指定的代码片段。SCDF仅对包含目标语句的基本块进行插桩，给定目标代码序列，SCDF可以生成按序到达代码序列并最终触发bug的input。进一步，本文提出了新的能量调度算法，根据其覆盖目标序列的能力来分配能量。

  * 基于源码实现
  * 对与序列相关的基本块插桩，避免较大的开销
  * 不在插桩阶段就像AFLGo那样进行过多的计算，运行完之后才会进行覆盖率计算等

- **实验效果**：在对真实软件的实验表明，SCDF在效率和效果方面优于AFLGo、BugRedux

> 1. https://wcventure.github.io/FuzzingPaper/Paper/ICPC19_Sequence.pdf


# Fuzzer of Papers
the link of paper and source code, and an abstract of paper

## Contents

1. [Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization](#not-all-coverage-measurements-are-equal-fuzzing-by-coverage-accounting-for-input-prioritization)
2. [MemLock: Memory Usage Guided Fuzzing](#memLock-memory-usage-guided-fuzzing)
3. [Sequence Coverage Directed Greybox Fuzzing](#sequence-coverage-directed-greybox-fuzzing)
4. [Angora: Efficient Fuzzing by Principled Search](angora-efficient-fuzzing-by-principled-search)
5. [FuzzingParmeSan: Sanitizer-guided Greybox Fuzzing](fuzzingParmeSan-sanitizer-guided-greybox-fuzzing[)

## Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization

作者：Wang, Yanhao and Jia, Xiangkun and Liu, Yuwei and Zeng, Kyle and Bao, Tiffany and Wu, Dinghao and Su, Purui

会议：NDSS 2020

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

作者：Wen, Cheng and Wang, Haijun and Li, Yuekang and Qin, Shengchao and Liu, Yang and Xu, Zhiwu and Chen, Hongxu and Xie, Xiaofei and Pu, Geguang and Liu, Ting

会议：42nd International Conference on Software Engineering，ICSE 2020 CCF A会

### 摘要

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

作者：Liang, Hongliang and Zhang, Yini and Yu, Yue and Xie, Zhuosi and Jiang, Lin

会议：2019 IEEE/ACM 27th International Conference on Program Comprehension (ICPC)

### 摘要

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

> 1. paper：https://wcventure.github.io/FuzzingPaper/Paper/ICPC19_Sequence.pdf

## Angora: Efficient Fuzzing by Principled Search

作者：Chen, Peng and Chen, Hao

会议：2018 IEEE Symposium on Security and Privacy (SP)

### 摘要

- **解决的问题**：

  提高模糊测试的效率，更好地生成输入来触发更多的程序状态

- **已有解决方案**：

  结合符号执行的模糊测试能够产生高质量的输入，但是它们的运行速度很慢，开销很大；基于随机变异来产生输入的模糊测试方法运行速度很快，但无法产生高质量的输入。

- **本文提出的创新方案概述**：

  本文提出了Angora, 一个新的基于变异的模糊测试工具。Angora 的主要目标是在不使用符号执行的前提下求解路径约束来提高代码覆盖率。为了更高效地解决路径约束， 提出了四个关键技术：

  1. 可适应的字节级别的污点跟踪：分析 input 中与条件判断相关的字节，仅对其进行变异，而不是变异整个 input
  2. 上下文敏感的分支计数：识别在不同上下文中相同的分支，将此作为衡量种子是否有趣的标准
  3. 基于梯度下降搜索的约束求解方法：将条件判断语句处的约束转换成函数，利用梯度下降的方法求解函数，实现类似符号执行的功能
  4. 输入长度的智能探索：使得读取数据的长度尽可能满足程序的需要，也即不盲目的增加输入的长度，当需要增加输入长度来触发新路径时才增加输入的长度

- **实验效果**：

  Angora在LAVA数据集和真实程序中比其他模糊测试工具能够找到更多的漏洞和覆盖更多的代码块。

> 1. paper：https://www.cs.ucdavis.edu/~hchen/paper/chen2018angora.pdf
> 2. code：https://github.com/AngoraFuzzer/Angora
> 3. video：https://www.youtube.com/watch?v=S4VChMYzpgc

## FuzzingParmeSan: Sanitizer-guided Greybox Fuzzing

作者：sterlund, Sebastian and Razavi, Kaveh and Bos, Herbert and Giuffrida, Cristiano

会议：29th USENIX Security  2020

### 摘要

- **解决的问题**：

改进导向性模糊测试，提升其漏洞覆盖率

- **已有解决方案**：

基于代码覆盖率的模糊测试认为覆盖率与漏洞覆盖率强相关，为了提升漏洞挖掘效果只是盲目的提升代码覆盖率。由于代码覆盖率对漏洞覆盖率是过拟合的，所以此方法并不理想，可能会花费很多的时间来发现漏洞。为此，导向性模糊测试通过引导 fuzz 至可能包含漏洞的基本块来解决此问题。这样可以极大的减少发现特定漏洞的时间，但是对漏洞覆盖率是欠拟合的

- **本文提出的创新方案概述**：

在本文中，我们提出了sanitizer-guided fuzzing，专门针对漏洞覆盖率进行了优化。主要观察是，现有的软件sanitizer插桩通常被用于检测模糊测试引起的错误情况，看其是否属于某种漏洞。但它们还可以作为一种通用且有效的机制来识别有趣的基本块，从而更好地引导模糊测试

- **实验效果**：

实验证明 ParmeSan 大大降低了实际漏洞挖掘的时间，覆盖相同漏洞的速度比现有的基于覆盖率的模糊测试（Angora）快37％，比导向的模糊测试（AFLGo）快288％。

> 1. paper：https://download.vusec.net/papers/parmesan_sec20.pdf
> 2. code：https://github.com/vusec/parmesan
> 3. slides：https://docs.google.com/presentation/d/1b6UjioGkbz54VSO-7nO1B34HCKr4IUv4J8_5U-1328U/edit#slide=id.g82cb7d858d_2_75


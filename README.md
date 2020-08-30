# Fuzzer of Papers
the link of paper and source code, and an abstract of paper

## Contents

1. [Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization](#not-all-coverage-measurements-are-equal-fuzzing-by-coverage-accounting-for-input-prioritization)

2. [MemLock: Memory Usage Guided Fuzzing](#memLock-memory-usage-guided-fuzzing)

3. [Sequence Coverage Directed Greybox Fuzzing](#sequence-coverage-directed-greybox-fuzzing)

4. [Angora: Efficient Fuzzing by Principled Search](#angora-efficient-fuzzing-by-principled-search)

5. [FuzzingParmeSan: Sanitizer-guided Greybox Fuzzing](#fuzzingparmesan-sanitizer-guided-greybox-fuzzing)

7. [TIFF: Using Input Type Inference To Improve Fuzzing](#TIFF-Using-Input-Type-Inference-To-Improve-Fuzzing)

7. [Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities](#Binary-level-Directed-Fuzzing-for-Use-After-Free-Vulnerabilities)

8. [Undangle-Early Detection of Dangling Pointers in Use-After-Free and Double-Free Vulnerabilities](#undangle-early-detection-of-dangling-pointers-in-use-after-free-and-double-free-vulnerabilities)

   

   

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

## Undangle-Early Detection of Dangling Pointers in Use-After-Free and Double-Free Vulnerabilities

作者：Caballero, Juan and Grieco, Gustavo and Marron, Mark and Nappa, Antonio

会议：Proceedings of the 2012 International Symposium on Software Testing and Analysis

### 摘要

- **解决的问题**：

  检测UAF、DF漏洞

- **已有解决方案**：

  当悬空指针指向的内存对象被释放时，导致指针指向了dead memory，随后该内存区域可能被重新分配或重写。UAF、DF漏洞难以识别且花费时间较多，这是由于悬空指针的创建、使用可能时间间隔很大。另外，为了理解漏洞的根本原因可能需要去分析内存中多个对象。如：有些悬空指针是由于忘记将被释放对象的指针置null而导致的。

  之前的工作主要是在悬空指针被使用时才能发现漏洞，提前检测技术在悬空指针出现时、使用前就可以检测到漏洞。

- **本文提出的创新方案概述**：

  本文设计、实现了提前检测技术Undangle。为了在运行时识别出不安全的悬空指针并最少化假阳性，我们将long-lived（长时间存在）悬空指针视为不安全的。为此，提前检测技术跟踪悬空指针的创建时间，当其存在时间超出提前定义好的时间窗口后将其识别为不安全的悬空指针。

  现有的内存调试工具提供了当使用悬空指针时有关程序状态的信息，但提供的有关悬空指针被创建的信息很少。本文提出的早期检测技术可自动确定崩溃是由UAF还是DF漏洞引起的，并在创建和使用悬空指针时收集有关程序状态的信息。

- **实验效果**：

  为了评估Undangle，对8个真实漏洞进行漏洞分析。结果表明，Firefox中的两个不同的漏洞具有共同的漏洞成因，并且它们的补丁程序不能完全修复潜在的错误，还在Firefox Web浏览器上识别出新的漏洞。

> 1. paper：https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/Undangle.pdf

## TIFF: Using Input Type Inference To Improve Fuzzing

作者：Jain, Vivek and Rawat, Sanjay and Giuffrida, Cristiano and Bos, Herbert

会议：Proceedings of the 34th Annual Computer Security Applications Conference（ACSAC-2018）

### 摘要

- **解决的问题**：

  fuzzing中对输入进行变异的步骤对提升代码覆盖率和触发bug来说至关重要。本文通过修改变异策略来最大化代码覆盖率从而发现更多的bug。

- **已有解决方案**：

  现有的方法大部分是盲目的进行变异来触发bug条件，有一些 smart fuzzer 来改进变异策略实现更好的代码覆盖，但是仍然低效，需要多次的变异操作。

- **本文提出的创新方案概述**：

  本文对输入中数据的类型进行推断，提出一种新的变异策略，不仅能提高代码覆盖率，同时保证大概率触发漏洞。例如，推断出是INT类型，就可以将其变异为边界值，挖掘整型溢出漏洞。

- **实验效果**：

  对实际应用程序的评估表明，基于类型推断的 fuzzer 比现有解决方案能更早触发bug，同时保持较高的代码覆盖率。例如，与现有的fuzzer 相比，在实际的应用程序和库（例如poppler，mpg123等）上，TIFF几乎在一半的时间内发现了bug，并且输入的数量少了一个数量级。 

### 框架

<img src="https://cdn.jsdelivr.net/gh/zytMatrix/images/posts/20200827152529.png" style="zoom:50%;" />

1. TIFF监控基本块和他们的执行频率，最终基于这些执行过的基本块计算输入的适应度值。任何执行了新基本块的输入会进行进一步的变异
2. 为了最大化代码覆盖率，TIFF提取input中两类数据类型：控制偏移类型和数据偏移类型
3. 此步是将输入变异为高代码覆盖率和进行错误检测的主要步骤
   * 首先考虑控制偏移类型，如果有与之相关的不变量（例如，cmp指令中的比较对象），它会使用相关信息来变异，或根据与此偏移量相关联的类型标签，对相应的偏移进行突变
   * 考虑输入中的非控制偏移的数据类型。TIFF的变异策略因输入字节的类型而异。具体而言，对于INT x类型的数据，TIFF根据x的大小变异为不寻常的值（例如，给定整数类型的极值），这种类型的突变主要针对整数溢出错误和堆溢出错误。对于数组类型的偏移量，TIFF插入任意长度的数据，这种类型的突变主要针对缓冲区溢出

> 1. paper: https://www.react-h2020.eu/m/filer_public/b9/64/b9646257-d406-42af-acc8-9260bab720c7/tiff_acsac18.pdf
> 2. code: https://github.com/vusec/TIFF

## Binary-level Directed Fuzzing for Use-After-Free Vulnerabilities

作者：Nguyen, Manh-Dung and Bardin, S{\'e}bastien and Bonichon, Richard and Groz, Roland and Lemerre, Matthieu

会议：International Symposium on Recent Advances in Intrusion Detection（RAID-2020）

### 摘要

- **解决的问题**：

  第一个针对二进制实现了导向fuzzer来”挖掘“UAF漏洞

  本文旨在设计一个有效的导向性 fuzz 来挖掘二进制而非源码中的 UAF 漏洞，面临的挑战有：

  1. **Complexity：**触发UAF漏洞需要对同一内存位置执行3个事件：分配、释放、使用，涉及到程序中的多个函数。而缓冲区溢出仅需要一次单独的内存越界访问。UAF的触发需要考虑时间、空间问题，相对来说更加复杂
  2. **Silence：**UAF漏洞经常没有明显的症状，如：仅仅体现出段错误。此时，fuzz 能判断出是crash，但不能知道是哪种内存错误。而现有的工具 ASan、VarGrind 由于较高的开销不适合集成至 fuzz 中

- **已有解决方案**：

  目前的 fuzzing 工具，很难挖掘出复杂的漏洞，如：UAF。这些漏洞需要满足非常特别的属性才能触发漏洞。我们需要将视线从仅包含缓冲区溢出漏洞的数据集 LAVA-M 转移至新的漏洞类型，如：UAF。

  现有的导向性 fuzz工具 AFLGo、HawkExe 并不能解决上述问题：

  1. 他们过于通用因此不能解决一些UAF漏洞相关的特定问题，如：时间问题，也即他们的引导标准并不考虑执行”序列“
  2. 他们完全不考虑UAF类型的漏洞，若将其产生的大量测试用例送至检测工具进行检测可能需要大量的时间
  3. 他们基于源码来插桩，开销很大，并且不能处理二进制的情况

- **本文提出的创新方案概述**：

  <img src="https://cdn.jsdelivr.net/gh/zytMatrix/images/posts/20200830160556.png" style="zoom:50%;" />

  * **输入**：二进制、Targets（**UAFuzz主要关注于bug重放，它的目标信息是bug trace，也即提前就知道UAF漏洞的trace信息**）

  * **计算CG、CFG**：

  * **Input Metrics：**

    * Target Similarity：$t_{P-3TP-B}(s,T)=<t_P(s,T),t_{3TP}(s,T),t_B(s,T))>$，组合首先选择在前缀中覆盖最多代码位置的种子，然后按序覆盖UAF事件最多的种子，最后选择到达 targets 中最多位置的种子。

    * UAF-based Distance：$$\Theta_{UAF}(f_a, f_b)\triangleq 
      \begin{cases}
      \beta=0.25~~~~ if ~f_a \rightarrow f_b 覆盖了序列中超过两个的UAF事件 \\
      1 ~~~~其他
      \end{cases}$$

      将本文的 edge 权重和 HAWKEYE 中的权重结合起来：$W_{UAFuzz}(f_a, f_b) \triangleq W_{Hawkeye}(f_a, f_b)*\Theta_{UAF}(f_a, f_b)$

    * Cut-edge Coverage： source 基本块和 sink 基本块之间的 cut edge 定义为一个 decision 节点的出边，因此存在一条从 source 基本块开始，经过此 edge 并到达 sink 基本块的路径。非 cut edge 是指它不是 cut edge，即没有从 source 到 sink 的路径通过该edge。若input执行的cut-edge越多，non-cut edge越少，则它更可能覆盖很多的目标代码位置。

  * **Seed Selection：**基于上述标准的Target Simility来选择 seed
  * **Power Schedule：**基于上述三个标准来分配能量，根据 seed 能有序的覆盖目标位置的数目$T_p(s,T)$按比例分配能量，同时seed distance d 和 cut-edge coverage es作为修正。$p(s,T) \triangleq (1+t_P(s, T))\times \tilde{e_s}(s,T)\times(1-\tilde{d_s(s,T)})$
  * **Bug Triage：**目标相似性度量允许 UAFUZZ 在运行时计算每个输入覆盖目标的序列。每当创建和执行每个种子后，即可免费获得此信息。我们利用它来预先判定可能触发bug的种子，即确实按顺序覆盖UAF的三个事件。然后，错误分类工具仅在这些预先确定的种子上运行，而其他种子则被丢弃，这能节省大量的错误分类时间

### 流程

<img src="https://cdn.jsdelivr.net/gh/zytMatrix/images/posts/20200830162455.png" style="zoom:50%;" />

如上所示：

1. 以初始seed、被测程序、从 bug trace 中抽取的 target location 信息为输入
2. 提出了三种专门用于 UAF 漏洞检测的种子衡量指标，种子选择策略倾向于选择在运行时可以覆盖更多target location的种子，能量调度算法根据其在 fuzz 过程中 seed 的分数来分配能量。
3. 最后，我们利用先前衡量种子的指标来预识别那些可能包含 UAF 漏洞的 seed，然后再将其传给分析工具（VALGRIND）以进行确认，避免无用的检查

> 1. paper: https://wcventure.github.io/FuzzingPaper/Paper/Arxiv20_BinaryUAF.pdf
> 2. code: https://github.com/strongcourage/uafuzz
> 3. slides：https://www.blackhat.com/us-20/briefings/schedule/#about-directed-fuzzing-and-use-after-free-how-to-find-complex--silent-bugs-20835
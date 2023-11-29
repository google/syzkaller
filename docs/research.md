# Research work based on syzkaller

Dear researchers, feel free to contact us at syzkaller@googlegroups.com if you need any assistance.

_newer first_
* [SyzDirect: Directed Greybox Fuzzing for Linux Kernel](https://dl.acm.org/doi/abs/10.1145/3576915.3623146)
* [KIT: Testing OS-Level Virtualization for Functional Interference Bugs](https://doi.org/10.1145/3575693.3575731)
* [SyzDescribe: Principled, Automated, Static Generation of Syscall Descriptions for Kernel Drivers](https://github.com/seclab-ucr/SyzDescribe)
* [GREBE: Unveiling Exploitation Potential for Linux Kernel Bugs](https://zplin.me/papers/GREBE.pdf)
* [Precise Detection of Kernel Data Races with Probabilistic Lockset Analysis](https://www.cs.columbia.edu/~gabe/files/oakland2023_pla.pdf)
* [Linux Kernel Enriched Corpus](https://github.com/cmu-pasta/linux-kernel-enriched-corpus) : [corpus.db](https://github.com/cmu-pasta/linux-kernel-enriched-corpus/raw/main/corpus.db)
* [HotBPF - An On-demand and On-the-fly Memory Protection](https://www.youtube.com/watch?v=1KSLTsgxaSU)
* [KASPER: Scanning for Generalized Transient Execution Gadgets in the Linux Kernel](https://www.vusec.net/projects/kasper/)
* [VaultFuzzer: A state-based approach for Linux kernel](https://hardenedvault.net/blog/2021-09-13-vaultfuzzer/)
* [Demystifying the Dependency Challenge in Kernel Fuzzing](https://conf.researchr.org/details/icse-2022/icse-2022-papers/89/Demystifying-the-Dependency-Challenge-in-Kernel-Fuzzing)
* [SyzVegas: Beating Kernel Fuzzing Odds with Reinforcement Learning](https://www.usenix.org/conference/usenixsecurity21/presentation/wang-daimeng)
* [SyzScope: Revealing High-Risk Security Impacts of Fuzzer-Exposed Bugs in Linux kernel](https://www.usenix.org/conference/usenixsecurity22/presentation/zou)
* [Rtkaller: State-aware Task Generation for RTOS Fuzzing](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/emsoft21.pdf)
* [BSOD: Binary-only Scalable fuzzing Of device Drivers](https://dmnk.co/raid21-bsod.pdf)
* [Torpedo: A Fuzzing Framework for Discovering Adversarial Container Workloads](https://vtechworks.lib.vt.edu/handle/10919/104159)
* [A Novel Dynamic Analysis Infrastructure to Instrument Untrusted Execution Flow Across User-Kernel Spaces](https://ieeexplore.ieee.org/abstract/document/9519439)
* [Healer](https://github.com/SunHao-0/healer) is a kernel fuzzer inspired by syzkaller. ([pdf](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/healer-sosp21.pdf))
* [SyzGen: Automated Generation of Syscall Specification of Closed-Source macOS Drivers](https://www.cs.ucr.edu/~zhiyunq/pub/ccs21_syzgen.pdf) ([source code](https://github.com/seclab-ucr/SyzGen_setup))
* [Snowboard: Finding Kernel Concurrency Bugs through Systematic Inter-thread Communication Analysis](https://dl.acm.org/doi/10.1145/3477132.3483549)
* [Undo Workarounds for Kernel Bugs](https://www.usenix.org/system/files/sec21fall-talebi.pdf) ([source code](https://trusslab.github.io/hecaton))
* [HFL: Hybrid Fuzzing on the Linux Kernel](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24018-paper.pdf)
* [A Novel Dynamic Analysis Infrastructure to Instrument Untrusted Execution Flow Across User-Kernel Spaces](https://www.computer.org/csdl/proceedings-article/sp/2021/893400a402/1mbmHSlbmvK)
* [Industry Practice of Coverage-Guided Enterprise Linux Kernel Fuzzing](http://wingtecher.com/themes/WingTecherResearch/assets/papers/fse19-linux-kernel.pdf)
* [Agamotto: Accelerating Kernel Driver Fuzzing with Lightweight Virtual Machine Checkpoints](https://www.usenix.org/conference/usenixsecurity20/presentation/song) ([source code](https://github.com/securesystemslab/agamotto))
* [Task selection and seed selection for Syzkaller using reinforcement learning](https://groups.google.com/d/msg/syzkaller/eKPD4ZpJ66o/UqO_K-SMFwAJ) (announce only)
* [Empirical Notes on the Interaction Between Continuous Kernel Fuzzing and Development](http://users.utu.fi/kakrind/publications/19/vulnfuzz_camera.pdf)
* [FastSyzkaller: Improving Fuzz Efficiency for Linux Kernel Fuzzing](https://iopscience.iop.org/article/10.1088/1742-6596/1176/2/022013)
* [Charm: Facilitating Dynamic Analysis of Device Drivers of Mobile Systems](https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-talebi.pdf)
([video](https://www.usenix.org/conference/usenixsecurity18/presentation/talebi),
[slides](https://www.usenix.org/sites/default/files/conference/protected-files/security18_slides_talebi.pdf),
[source code](https://trusslab.github.io/charm))
* [ALEXKIDD-FUZZER: Kernel Fuzzing Guided by Symbolic Information](https://www.cerias.purdue.edu/assets/symposium/2018-posters/829-D1B.pdf)
* [DIFUZE: Interface Aware Fuzzing for Kernel Drivers](https://acmccs.github.io/papers/p2123-corinaA.pdf)
* [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation](http://www.cs.columbia.edu/~suman/docs/moonshine.pdf)
* [RAZZER: Finding Kernel Race Bugs through Fuzzing](https://lifeasageek.github.io/papers/jeong:razzer.pdf)
* [SemFuzz: Semantics-based Automatic Generation of Proof-of-Concept Exploits](https://www.informatics.indiana.edu/xw7/papers/p2139-you.pdf)
* [Towards Automating Exploit Generation for Arbitrary Types of Kernel Vulnerabilities](https://i.blackhat.com/us-18/Thu-August-9/us-18-Wu-Towards-Automating-Exploit-Generation-For-Arbitrary-Types-of-Kernel-Vulnerabilities-wp.pdf)
* [KOOBE: Towards Facilitating Exploit Generation of Kernel Out-Of-Bounds Write Vulnerabilities](https://www.usenix.org/system/files/sec20summer_chen-weiteng_prepub.pdf)
* [Synthesis of Linux Kernel Fuzzing Tools Based on Syscall](http://dpi-proceedings.com/index.php/dtcse/article/download/14990/14503)
* [Drill the Apple Core: Up & Down](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Juwei_Lin-Drill-The-Apple-Core.pdf)
* [WSL Reloaded](https://www.slideshare.net/AnthonyLAOUHINETSUEI/wsl-reloaded)

# Other kernel fuzzing work

* [Hydra: Finding Semantic Bugs in File Systems with an Extensible Fuzzing Framework](https://squizz617.github.io/pubs/hydra-sosp19.pdf) ([github](https://github.com/sslab-gatech/hydra))
* [Janus: Fuzzing File Systems via Two-Dimensional Input Space Exploration](https://gts3.org/assets/papers/2019/xu:janus.pdf) ([github](https://github.com/sslab-gatech/janus))
* [CoLaFUZE: Coverage-Guided and Layout-Aware Fuzzing for Android Drivers](https://www.jstage.jst.go.jp/article/transinf/E104.D/11/E104.D_2021NGP0005/_pdf)
* [KRACE: Data Race Fuzzing for Kernel File Systems](https://www.cc.gatech.edu/~mxu80/pubs/xu:krace.pdf)
* [trinity](https://github.com/kernelslacker/trinity)
* [kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels](https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-schumilo.pdf) (bridges AFL and Intel PT)
* [kernel-fuzzing](https://github.com/oracle/kernel-fuzzing) (bridges AFL and KCOV)
* [A gentle introduction to Linux Kernel fuzzing](https://blog.cloudflare.com/a-gentle-introduction-to-linux-kernel-fuzzing/) (bridges AFL and KCOV)
* [IMF: Inferred Model-based Fuzzer](https://acmccs.github.io/papers/p2345-hanA.pdf)

Also see [tech talks page](/docs/talks.md).

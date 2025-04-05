> [!WARNING]
>
> **请注意，这是社区驱动的官方 syzkaller 文档翻译。当前文档的最新版本（英文版）可在 [docs/contributing.md](/docs/contributing.md) 中找到。**

# 如何为 syzkaller 项目做贡献

如果你想为本项目做出贡献，请按照下面的[指南](contributing.md#guidelines)提交拉取请求。

如果这是你第一次向 syzkaller 提交拉取请求，你需要[签署 Google CLA](https://cla.developers.google.com/)，
并在第一次提交时将自己添加到 [AUTHORS](/AUTHORS)/[CONTRIBUTORS](/CONTRIBUTORS) 文件中。

## 工作内容

扩展/改进 [系统调用描述](/docs/syscall_descriptions.md) 一直是个好主意。

[错误跟踪器](https://github.com/google/syzkaller/issues) 中未分配的议题是值得去做的，但其中有些议题可能比较复杂。

要贡献代码或系统调用描述，你至少需要能够构建并运行 syzkaller，请参阅[此处](/docs/setup.md)的说明。

## 指南

如果您想做一些并不微小的事情，请先在 [syzkaller@googlegroups.com](https://groups.google.com/forum/#!forum/syzkaller) 邮件列表上简要描述，以便在高层面的方法/设计上达成一致，且避免贡献者之间的重复工作。

将大改动拆分成逻辑上连贯的小提交。小的提交更容易、更快地进行审核和迭代。

所有可以合理测试的内容都应进行测试。

为了其他用户能方便地使用新特性，请提供足够的文档说明。

保持代码、测试、注释、文档、日志/错误信息的风格与现有风格一致。

持续集成（CI）系统会运行大量测试和一些 [意见] 式检查。它们需要通过。你可以使用 `make presubmit` 进行本地测试，如果没有安装某些先决条件，你可以尝试使用 `syz-env` （见下文）。

### 提交

提交信息应遵循以下模板：

```
dir/path: 单行描述
<空行>
扩展的多行描述，包括
您要解决的问题以及如何解决问题。
```

`dir/path` 是本次提交更改的主目录的相对路径（参见 [提交历史](https://github.com/google/syzkaller/commits/master) 中的示例）。如果多个软件包/目录发生重大改动，则允许使用以下格式：
```
dir1/path1, dir2/path2: 单行描述
```
不过，如果目录仅有细微改动，则不应包括在内。
对于普遍的更改，可以使用以下格式：
```
all: 单行描述
```

请注意标点符号，特别是：

- `单行描述` *不*应该以大写字母开头。
- `单行描述` 末尾*没有点*。
- `扩展的多行描述` 是带有大写字母和圆点的全英文句子。

提交信息行长度限制为 120 个字符。

还有:

- 如果您的提交修复了一个议题，请在提交信息中加入 `Fixes #NNN` 行（其中 `NNN` 是议题编号）。这将自动关闭议题。如果您需要提及议题，请添加 `Update #NNN`。
- 对于系统调用描述，`*.const` 文件应该与 `*.txt` 的更改在同一提交中被合入。

### 拉取请求

- 在发送拉取请求前，将你的工作分支变基到主分支以避免合并冲突。
- 运行 `make presubmit` 并确保通过后再发送 PR。
  该操作可能需要安装一些额外的软件包（请尝试 `sudo make install_prerequisites`）。
- 在拉取请求标题中提供简短的高级描述。
  拉取请求文本大多无关紧要，所有细节都应在提交信息中说明。
- 如果您被要求在拉取请求中添加一些修正，请将修正压入旧提交中。

### 如何在 Github 上创建一个拉取请求

- 首先，您需要一个自己的 syzkaller 仓库的复刻 git 仓库。导航到 [github.com/google/syzkaller](https://github.com/google/syzkaller)，然后点击页面右上角的 "Fork" 按钮。这将创建 `https://github.com/YOUR_GITHUB_USERNAME/syzkaller` 仓库。

- 请切换到 syzkaller 主版本库，如果尚未进行这一步。最简单的方法是运行 `git clone https://github.com/google/syzkaller`，这将在当前工作目录中切换到该仓库。
- 请记得 `export PATH=$GOPATH/bin:$PATH`，如果尚未导出 PATH 到环境变量。
- 然后将您的仓库添加为附加源：

    ```shell
    cd syzkaller
    git remote add my-origin https://github.com/YOUR_GITHUB_USERNAME/syzkaller.git
    git fetch my-origin
    git checkout -b my-branch my-origin/master
    ```

这会将您的仓库添加到 git origin `my-origin`，并基于 `master` 分支创建并切换新的分支 `my-branch` 。

- 根据需要更改/添加文件。
- 将更改提交到本地。为此，你需要对所有更改的文件运行 `git add`，例如 `git add sys/linux/sys.txt`。你可以运行 `git status` 查看有哪些文件被修改/创建。当所有文件都添加完毕后（`git status` 显示 `Changes not staged for commit` 部分没有文件，并且 `Untracked files` 部分没有相关文件），运行 `git commit` 并在你的编辑器中输入提交描述。
- 在本地运行测试（`make install_prerequisites`，然后执行 `make presubmit`）。
- 使用 `git push my-origin my-branch` 将提交推送到 github 上的复刻仓库。
- 导航至 [github.com/google/syzkaller](https://github.com/google/syzkaller)，你会看到绿色的 `比较 & 拉取请求` 按钮，按下它。然后按 `创建拉取请求`。现在你的拉取请求应该会出现在[拉取请求页面](https://github.com/google/syzkaller/pulls)上。
- 如果你由于任何原因看不到 `创建拉取请求` 按钮，你可以手动创建拉取请求。为此，请导航至[拉取请求页面](https://github.com/google/syzkaller/pulls)，按下 `新的拉取请求`，然后按下 `横叉比较` 并选择 `google/syzkaller`/`master` 作为基础，选择 `YOUR_GITHUB_USERNAME/syzkaller`/`my-branch` 作为比较，然后按下 `创建拉取请求`。
- 如果在创建了拉取请求后，你决定对 `my-branch` 中的提交进行变基（例如，将它们变基到更新的 master 上），则需要执行一次强制推送：`git push -f my-origin my-branch`。

### 使用 syz-env

开发 syzkaller 需要安装大量工具（Go 工具链、C/C++ 交叉编译器、golangci-lint 等）。安装所有这些工具可能会很麻烦，例如由于软件包损坏/缺失。[syz-env](/tools/syz-env) 提供了一个基于 Docker 容器的密封开发环境。如果尚未安装 Docker，请参阅[文档](https://docs.docker.com/engine/install)，特别是关于启用 [sudo-less](https://docs.docker.com/engine/install/linux-postinstall) 的 Docker（Googlers 参见 go/docker）。

建议为 `syz-env` 脚本创建别名：

```
alias syz-env="$(go env GOPATH)/src/github.com/google/syzkaller/tools/syz-env"
```

然后，几乎所有的 make 调用都可以用它来封装：

```
syz-env make format
syz-env make presubmit
syz-env make extract SOURCEDIR=$(readlink -f ~/linux)
```

或其他命令/脚本，例如：

```
syz-env go test -short ./pkg/csource
```

或者，你也可以只使用 `syz-env` 来在容器内运行 shell 并查看。

要将 `syz-env` 容器更新到最新版本，请执行以下操作：

``` bash
docker pull gcr.io/syzkaller/env
```

如果你无法访问 `gcr.io` 登记处，在 `docker.pkg.github.com` 登记处中也有一个镜像。要使用它，你需要使用你的 Github 账户来[验证 Docker](https://docs.github.com/en/packages/using-github-packages-with-your-projects-ecosystem/configuring-docker-for-use-with-github-packages)：

```
docker login https://docker.pkg.github.com
```

然后拉取镜像，并将其重新标记为 `syz-env` 所期望的名称：

```
docker pull docker.pkg.github.com/google/syzkaller/env
docker tag docker.pkg.github.com/google/syzkaller/env gcr.io/syzkaller/env
```

#!/bin/bash -x

set -e

echo "\e[36m[+]Setup workspace\e[0m"
WS=/local/mnt/workspace/$USER/go
if [ ! -e /local/mnt/workspace ]; then
  WS=~/workspace/go
fi
mkdir -p $WS

if [ "$(cat ~/.syzkaller | grep '^export GOROOT=')" == "" ]; then
  echo "export GOROOT=$WS/go" > ~/.syzkaller
  export GOROOT=$WS/go
fi
if [ "$(cat ~/.syzkaller | grep '^export GOPATH=')" == "" ]; then
  echo "export GOPATH=$WS" >> ~/.syzkaller
  export GOPATH=$WS
fi
if [ "$(echo $PATH | grep $GOROOT/bin)" == "" ]; then
  echo "export PATH=\$PATH:\$GOROOT/bin:\$GOPATH/bin" >> ~/.syzkaller
  export PATH=$PATH:$GOROOT/bin:$GOPATH/bin
fi
if [ "$(cat ~/.syzkaller | grep '^alias syzkaller=')" == "" ]; then
  echo "alias syzkaller=\"cd $GOPATH/src/github.com/google/syzkaller/\"" >> ~/.syzkaller
  alias syzkaller="cd $GOPATH/go/src/github.com/google/syzkaller/"
fi

echo "\e[36m[+]Setup go\e[0m"
cd $WS
rm -rf go
wget -qO- https://dl.google.com/go/go1.9.2.linux-amd64.tar.gz | tar -zxf -
if [ "$(cat ~/.bashrc | grep '^source ~/.syzkaller')" == "" ]; then
  echo "source ~/.syzkaller" >> ~/.bashrc
fi
source ~/.syzkaller
which go
go version

echo "\e[36m[+]Setup syzkaller\e[0m"
mkdir -p $WS/src/github.com/google/
cd $WS/src/github.com/google
if [ ! -d syzkaller ]; then
  go get -u -d github.com/google/syzkaller/...
  cd syzkaller
  git remote add qcom https://github.qualcomm.com/LinuxSecurity/syzkaller
  git fetch qcom
  branch=$(git branch -a | grep qcom-20 | tail -1 | awk -F'/' '{print $NF}')
  git checkout -b $branch qcom/$branch
fi
sudo apt update
sudo apt install linux-headers-amd64 -y || true
cd $WS/src/github.com/google/syzkaller
make install_prerequisites
sudo ln -sf $(ls /usr/bin/clang-format-* | grep clang-format-[0-9]) /usr/bin/clang-format

echo "\e[36m[+]Build syzkaller\e[0m"
./build.sh

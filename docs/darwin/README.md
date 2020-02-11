# Darwin/XNU

`Darwin/XNU` is not supported at the moment.

[panicall](https://twitter.com/panicaII) has ported
([[1]](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Juwei_Lin-Drill-The-Apple-Core.pdf)
([video](https://www.youtube.com/watch?v=zDXyH8HxTwg)),
[[2]](https://conference.hitb.org/hitbsecconf2019ams/materials/D2T2%20-%20PanicXNU%203.0%20-%20Juwei%20Lin%20&%20Junzhi%20Lu.pdf))
syzkaller to `Darwin/XNU` and that has found more than
[50 bugs](https://twitter.com/panicaII/status/1070696972326133760) including
`CVE-2018-4447` and `CVE-2018-4435` mentioned in
[Apple security updates](https://support.apple.com/en-us/HT209341).

`Darwin/XNU` is [open-source](https://github.com/opensource-apple/xnu) and has
[KASAN](https://github.com/apple/darwin-xnu/blob/master/san/kasan.c).
Latest versions also contain KCOV-like support for coverage;
it's not uploaded to github mirror yet, but this
[tarball](https://opensource.apple.com/tarballs/xnu/xnu-6153.11.26.tar.gz)
contains `san/ksancov.{h,c}`.

[PureDarwin](http://www.puredarwin.org/) may be used to create VM images suitable for fuzzing.

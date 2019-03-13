# Darwin/XNU

`Darwin/XNU` is not supported at the moment.

[panicall](https://twitter.com/panicaII) has
[ported](https://i.blackhat.com/eu-18/Wed-Dec-5/eu-18-Juwei_Lin-Drill-The-Apple-Core.pdf)
([video](https://www.youtube.com/watch?v=zDXyH8HxTwg))
syzkaller to `Darwin/XNU` and that has found more than
[50 bugs](https://twitter.com/panicaII/status/1070696972326133760) including
`CVE-2018-4447` and `CVE-2018-4435` mentioned in
[Apple security updates](https://support.apple.com/en-us/HT209341).

`Darwin/XNU` is [open-source](https://github.com/opensource-apple/xnu) and has
[KASAN](https://github.com/apple/darwin-xnu/blob/master/san/kasan.c),
but no KCOV at the moment (though not required for intial support).

[PureDarwin](http://www.puredarwin.org/) may be used to create VM images suitable for fuzzing.

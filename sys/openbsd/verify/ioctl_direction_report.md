# OpenBSD ioctl direction triage report

Scope: `sys/openbsd/*.txt` ioctl descriptors, checked against current OpenBSD kernel sources in `~/openbsd-src/sys`.

Date: 2026-03-18

## Method

1. Parsed all OpenBSD syzlang `ioctl$...` declarations.
2. Compared declared pointer direction (`ptr[in|out|inout]`) against ioctl direction bits encoded in extracted constants (`*.txt.const`).
3. For each mismatch, reviewed corresponding kernel headers and ioctl handlers to classify as:
   - **Real descriptor bug** (syzlang direction/type should be fixed), or
   - **Intentional/ABI quirk** (header `_IOWR`/`_IO` does not reflect practical usage), or
   - **Needs deeper review**.

This report intentionally focuses on direction and ABI usage only.

## Summary

- Total mismatches found by script: **35**
- Classified as **real descriptor bugs**: **13**
- Classified as **intentional/ABI quirks**: **22**
- Unclassified: **0**

Already fixed in this branch before this report:
- `AUDIO_MIXER_WRITE` in `dev_audio.txt` (`ptr[in]` -> `ptr[inout]`).

---

## A) Real descriptor bugs

### 1) `sys/openbsd/dev_bpf.txt`

- `BIOCGDLTLIST` (`_IOWR`) is modeled as `ptr[out, bpf_dltlist]`.
  - Header: `sys/net/bpf.h` (`#define BIOCGDLTLIST _IOWR('B',123, struct bpf_dltlist)`)
  - Handler (`sys/net/bpf.c`) needs user-provided `bfl_len` and `bfl_list` pointer as input and returns results.
  - **Fix**: ioctl arg should be `ptr[inout, bpf_dltlist]`.

- `BIOCSBLEN` (`_IOWR`) is modeled as `ptr[in, int32]`.
  - Header: `sys/net/bpf.h` (`#define BIOCSBLEN _IOWR('B',102, u_int)`)
  - Handler clamps requested size and writes adjusted value back (`*(u_int *)addr = ...`).
  - **Fix**: use `ptr[inout, int32]`.

### 2) `sys/openbsd/dev_dri.txt`

- `DRM_IOCTL_VERSION` (`DRM_IOWR`) is modeled as `ptr[out, drm_version]`.
  - Header: `sys/dev/pci/drm/include/uapi/drm/drm.h`
  - `drm_version` requires input lengths/pointers for strings and returns values.
  - **Fix**: use `ptr[inout, drm_version]`.

### 3) `sys/openbsd/dev_pci.txt`

- `PCIOCREAD` (`_IOWR`) is modeled as `ptr[out, pci_io]`.
  - Header: `sys/sys/pciio.h`
  - Handler (`sys/dev/pci/pci.c`) reads selector/register/width from input and writes `pi_data`.
  - **Fix**: `ptr[inout, pci_io]`.

- `PCIOCGETROM` (`_IOWR`) is modeled as `ptr[out, pci_rom]`.
  - Header: `sys/sys/pciio.h`
  - Handler reads selector and user buffer/length; writes ROM data and `pr_romlen`.
  - **Fix**: `ptr[inout, pci_rom]`.

### 4) `sys/openbsd/dev_vmm.txt`

`VMM_IOC_*` are `_IOWR` and contain mixed input/output fields in current `sys/dev/vmm/vmm.h`:

- `VMM_IOC_CREATE`: currently `ptr[in, vm_create_params]`.
  - `vm_create_params` has output fields (`vcp_id`, `vcp_poscbit`, `vcp_asid[]`).
  - **Fix**: `ptr[inout, vm_create_params]`.

- `VMM_IOC_INFO`: currently `ptr[out, vm_info_params]`.
  - Requires input `vip_size` and `vip_info` pointer, returns `vip_info_ct` and pointed data.
  - **Fix**: `ptr[inout, vm_info_params]`.

- `VMM_IOC_READREGS`: currently `ptr[out, vm_rwregs_params]`.
  - Requires input VM/vCPU ids and mask; returns selected registers.
  - **Fix**: `ptr[inout, vm_rwregs_params]`.

- `VMM_IOC_RUN`: currently `ptr[in, vm_run_params]`.
  - Includes in/out fields (`vrp_exit` content updated, exit reason/irqready output).
  - **Fix**: `ptr[inout, vm_run_params]`.

### 5) `sys/openbsd/dev_vnd.txt`

- `VNDIOCGET` (`_IOWR`) currently `ptr[in, vnd_user]`.
  - `vnu_unit` is input selector, remaining fields are output.
  - **Fix**: `ptr[inout, vnd_user]`.

- `VNDIOCSET` (`_IOWR`) currently `ptr[in, vnd_ioctl]`.
  - Kernel writes back `vnd_size` on success.
  - **Fix**: `ptr[inout, vnd_ioctl]`.

### 6) `sys/openbsd/tty.txt`

- `TIOCOUTQ` (`_IOR`) currently `ptr[in, int32]`.
  - Header: `sys/sys/ttycom.h`
  - Handler (`sys/kern/tty.c`) writes queue size (`*(int*)data = ...`).
  - **Fix**: `ptr[out, int32]`.

- `TIOCSTAT` (`_IO`) currently declared with arg `ptr[out, int32]`.
  - Header indicates no argument; handler uses none.
  - **Fix**: remove arg from descriptor.

### 7) `sys/openbsd/wscons.txt`

- `WSMOUSEIO_GETPARAMS` (`_IOW`) currently `ptr[out, wsmouse_parameters]`.
  - Header: `sys/dev/wscons/wsconsio.h`
  - Handler (`sys/dev/wscons/wsmouse.c`) reads user-provided parameter array (`copyin`) and writes values back (`copyout`).
  - **Fix**:
    - ioctl arg should be `ptr[inout, wsmouse_parameters]`.
    - `wsmouse_parameters.params` should be `ptr[inout, array[wsmouse_param]]`.

---

## B) Intentional / ABI-quark mismatches (no immediate change required)

These mismatches are consistent with historical `_IOWR`/`_IO` encodings while kernel code uses data mostly in one direction or in nonstandard ways.

### `sys/openbsd/dev_diskmap.txt`
- `DIOCMAP` (`_IOWR`) with `ptr[in, dk_diskmap]`.
- Kernel primarily consumes input struct fields; output happens via `copyoutstr` to nested `device` pointer, not by mutating struct fields.

### `sys/openbsd/dev_dri.txt`
- `DRM_IOCTL_MODE_RMFB`, `DRM_IOCTL_MODE_OBJ_SETPROPERTY`, `DRM_IOCTL_MODE_ATOMIC` are `DRM_IOWR` but practically input-oriented in current stack.

### `sys/openbsd/dev_pci.txt`
- `PCIOCWRITE` is `_IOWR` but practically input-only.

### `sys/openbsd/dev_pf.txt`
- `DIOCSETDEBUG`, `DIOCSETHOSTID`, `DIOCSETREASS`, `DIOCSETSYNCOOKIES`, `DIOCSETSTATUSIF`, `DIOCCLRSTATUS`, `DIOCXEND`:
  `_IOWR` but used as input-oriented.
- `DIOCGETSTATUS`, `DIOCGETSYNFLWATS`: `_IOWR` but output-oriented.

### `sys/openbsd/dev_speaker.txt`
- `SPKRTUNE` is `_IO` yet driver interprets `data` as pointer to pointer and performs `copyin` from user buffer.
- Existing syzlang shape is imperfect, but mismatch itself is legacy ABI oddity rather than simple direction bug.

### `sys/openbsd/wscons.txt`
- `KDMKTONE`, `KDSETLED`, `KDSETMODE`, `VT_ACTIVATE`, `VT_RELDISP`, `VT_WAITACTIVE` are `_IO` in USL compatibility headers but handlers in `wsdisplay_compat_usl.c` read values from `data`.
- Keeping explicit argument modeling is reasonable for fuzzing despite encoded direction `none`.

---

## Raw mismatch list (script output)

```
sys/openbsd/dev_bpf.txt:18:BIOCGDLTLIST:expected=inout:actual=out
sys/openbsd/dev_bpf.txt:28:BIOCSBLEN:expected=inout:actual=in
sys/openbsd/dev_diskmap.txt:15:DIOCMAP:expected=inout:actual=in
sys/openbsd/dev_dri.txt:27:DRM_IOCTL_VERSION:expected=inout:actual=out
sys/openbsd/dev_dri.txt:51:DRM_IOCTL_MODE_RMFB:expected=inout:actual=in
sys/openbsd/dev_dri.txt:62:DRM_IOCTL_MODE_OBJ_SETPROPERTY:expected=inout:actual=in
sys/openbsd/dev_dri.txt:72:DRM_IOCTL_MODE_ATOMIC:expected=inout:actual=in
sys/openbsd/dev_pci.txt:12:PCIOCREAD:expected=inout:actual=out
sys/openbsd/dev_pci.txt:13:PCIOCWRITE:expected=inout:actual=in
sys/openbsd/dev_pci.txt:14:PCIOCGETROM:expected=inout:actual=out
sys/openbsd/dev_pf.txt:27:DIOCSETDEBUG:expected=inout:actual=in
sys/openbsd/dev_pf.txt:28:DIOCSETHOSTID:expected=inout:actual=in
sys/openbsd/dev_pf.txt:29:DIOCSETREASS:expected=inout:actual=in
sys/openbsd/dev_pf.txt:30:DIOCSETSYNCOOKIES:expected=inout:actual=in
sys/openbsd/dev_pf.txt:33:DIOCGETSTATUS:expected=inout:actual=out
sys/openbsd/dev_pf.txt:34:DIOCSETSTATUSIF:expected=inout:actual=in
sys/openbsd/dev_pf.txt:35:DIOCCLRSTATUS:expected=inout:actual=in
sys/openbsd/dev_pf.txt:77:DIOCXEND:expected=inout:actual=in
sys/openbsd/dev_pf.txt:88:DIOCGETSYNFLWATS:expected=inout:actual=out
sys/openbsd/dev_speaker.txt:15:SPKRTUNE:expected=none:actual=in
sys/openbsd/dev_vmm.txt:17:VMM_IOC_CREATE:expected=inout:actual=in
sys/openbsd/dev_vmm.txt:18:VMM_IOC_INFO:expected=inout:actual=out
sys/openbsd/dev_vmm.txt:19:VMM_IOC_READREGS:expected=inout:actual=out
sys/openbsd/dev_vmm.txt:21:VMM_IOC_RUN:expected=inout:actual=in
sys/openbsd/dev_vnd.txt:14:VNDIOCGET:expected=inout:actual=in
sys/openbsd/dev_vnd.txt:15:VNDIOCSET:expected=inout:actual=in
sys/openbsd/tty.txt:25:TIOCOUTQ:expected=out:actual=in
sys/openbsd/tty.txt:48:TIOCSTAT:expected=none:actual=out
sys/openbsd/wscons.txt:20:KDMKTONE:expected=none:actual=in
sys/openbsd/wscons.txt:21:KDSETLED:expected=none:actual=in
sys/openbsd/wscons.txt:22:KDSETMODE:expected=none:actual=in
sys/openbsd/wscons.txt:24:VT_ACTIVATE:expected=none:actual=in
sys/openbsd/wscons.txt:29:VT_RELDISP:expected=none:actual=in
sys/openbsd/wscons.txt:31:VT_WAITACTIVE:expected=none:actual=in
sys/openbsd/wscons.txt:89:WSMOUSEIO_GETPARAMS:expected=in:actual=out
```

---

## Recommended next patch set (if we decide to fix all real bugs)

- `dev_bpf.txt`: BIOCGDLTLIST/BIOCSBLEN
- `dev_dri.txt`: DRM_IOCTL_VERSION
- `dev_pci.txt`: PCIOCREAD/PCIOCGETROM
- `dev_vmm.txt`: VMM_IOC_CREATE/INFO/READREGS/RUN
- `dev_vnd.txt`: VNDIOCGET/VNDIOCSET
- `tty.txt`: TIOCOUTQ/TIOCSTAT
- `wscons.txt`: WSMOUSEIO_GETPARAMS (+ `wsmouse_parameters.params` direction)

After changes: re-run `syz-extract` for touched files and diff corresponding `.const` files.

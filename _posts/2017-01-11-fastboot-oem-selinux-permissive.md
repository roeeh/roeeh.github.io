---
layout: post
title: fastboot oem selinux permissive
author: Roee Hay
date: '2017-01-11'
tags:

---

I have just [disclosed] a new vulnerability affecting One Plus 3 (and maybe 3T!) running the latest version of OxygenOS (4.0.1 at the time of writing).
Similarly to our other recently disclosed vulnerabilities, One Plus 3's bootloader has an unsafe `fastboot oem` command which is available even if the bootloader is locked.

The attacker can reboot the device into the `fastboot` mode, which could be done without any authentication -- A physical attacker can press the ‘Volume Up' button during device boot, where an attacker with ADB access can issue the `adb reboot bootloader` command.

Then, the attacker can put the platform's SELinux in permissive mode, which severly weakens it,  by simply issuing:
{% highlight C %}
fastboot oem selinux permissive
{% endhighlight %}


And indeed, SELinux is then set to permissive mode:
{% highlight C %}
OnePlus3:/ $ getenforce
Permissive
OnePlus3:/ $
{% endhighlight %}

[disclosed]: https://exchange.xforce.ibmcloud.com/collection/OnePlus-3-fastboot-oem-selinux-permissive-Vulnerability-d38d8557f1a01570539151c782d52aaf "disclosed"
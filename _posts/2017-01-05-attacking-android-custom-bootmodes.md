---
layout: post
title: fastboot oem {config bootmode, enable-bp-tools/hw-factory}
author: Roee Hay
date: '2017-01-05'
tags:

---

In the [January 2017 Android Security Bulletin](https://source.android.com/security/bulletin/2017-01-01.html), Google provided a patch to `CVE-2016-8467`.
This is a high severity vulnerability in Nexus 6 & 6P (with a lower impact on Nexus 6P) we disclosed to Google in June which allows enabling of hidden USB interfaces. This, together with another vulnerability (`CVE-2016-6678`) we found in Nexus 6 can be combined for conducting several attacks.

Together with Michael Goberman of my team, we released a paper with all of the technical details:

<a href="https://www.docdroid.net/dxKUj5c/attacking-nexus-6-6p-custom-bootmodes.pdf.html"><img alt="Attacking Nexus 6/6P Custom Bootmodes" title="Attacking Nexus 6/6P Custom Bootmodes" src="/images/cve-2016-8467-paper.png" width="416px" height="344px"></a>

The hidden USB interfaces are enabled when the bootloader inserts the `androidboot.mode` argument into the kernel command line. PC malware or a malicious charger can force the bootloader of Nexus 6/6P to boot with the special bootmode parameter if ADB is enabled on the device. The user will need to authorize the PC or charger on the device once connected, if it hasn't been permanently authorized before the attack. Then, the attacker can just issue the following commands, in order to reboot the device with the special bootmode that enables the interfaces:

{% highlight C %}
adb reboot
fastboot oem config bootmode {bp-tools,factory} (N6)
fastboot oem bp-tools-on (N6, option 2)
fastboot oem {enable-bp-tools,enable-hw-factory} (N6P)
fastboot reboot
{% endhighlight %}

The full chain of events that end with the enablement of the USB interfaces is further explained in our [paper].

Every future boot from this point forward will have the bootmode configuration enabled, i.e. the attack is persistent and no longer requires ADB to be running (but still requires USB access). Essentially this means that the attacker only needs the victim to enable ADB once. Moreover, a lucky attacker may just wait for the device to be in the fastboot mode, which does not require any authorization from the victim, however, less likely.

Physical attackers can also boot the device with a custom bootmode, by selecting “BP-Tools” or “Factory” under the fastboot UI.

![BP-Tools selection on fastboot](/images/bp-tools-6p.png)


The first attack we describe in our [paper] allows an adversary with USB access to the device, to practically own the Nexus 6 modem, by accessing its diagnostics interface. For example we managed to record phone calls (UMTS vocoder frames), sniff LTE data and much more.

![Waveform of recorded call](/images/waveform.png)


![LTE data sniff](/images/lte_data_sniff.png)

The second attack also works on Nexus 6P, and enables access to the modem's AT interface. By accessing that interface the attacker can send / eavesdrop SMS messages (which may allow the attacker to bypass two-factor authentication), see phone calls' information, change radio settings (e.g. downgrade to GSM or switch off packet- and/or circuit-switching), etc.

![SMS Sniffing on Nexus 6P via AT](/images/6p_sms_sniff.png)


As for `CVE-2016-6678`, one of the USB interface that gets enabled in Nexus 6 when booting with the custom bootmode identifies itself as `Motorola Test Comamnd`, which is actually an Ethernet-over-USB gadget. The kernel driver which is responsible for this interface is [`f_usbnet`](https://android.googlesource.com/kernel/msm.git/+/android-msm-shamu-3.10-marshmallow/drivers/usb/gadget/f_usbnet.c). Interestingly, we found a vulnerabiliy in the f_usbnet driver itself - 4 or 5 bytes of uninitalized kernel data are padded to every Ethernet frame that is carried over USB:

{% highlight c %}
static int usb_ether_xmit(struct sk_buff *skb, struct net_device *dev) {
	struct usbnet_context *context = netdev_priv(dev);
	struct usb_request *req;
	unsigned long flags;
	unsigned len;
	int rc;
	req = usb_get_xmit_request(STOP_QUEUE, dev);
	....
	/* Add 4 bytes CRC */
	skb->len += 4;

	/* ensure that we end with a short packet */
	len = skb->len;
	if (!(len & 63)|| !(len & 511))
		len++;
	req->context = skb;
	req->buf = skb->data;
	req->length = len;

	rc = usb_ep_queue(context->bulk_in, req, GFP_KERNEL);
	....
	return 0;
}
{%endhighlight%}
 This leak may contain sensitive data, and may aid in further exploitation. You can see the leak under the 'padding' field:

![Motorola USBNet leak](/images/usbnet_leak.png)

Another interesting consequence of the vulnerability in 6P is that the ADB interface would become enabled even if it was disabled in the 'Developer Settings' UI. This, allows the physical attacker to open up an ADB session with the device if he has access to an ADB-authorized PC. It turns out that the attacker can cause the ADB host (running under the victim's PC), to RSA-sign the ADB authentication token even if the PC is locked. In addition to the physical attacker, PC malware on an ADB-authorized machine may also exploit `CVE-2016-8467` in order to enable ADB and install Android malware. The PC malware will wait for the victim to place the device in the fastboot mode in order to exploit the vulnerability.

Google rated `CVE-2016-8467` with High severity and mitigated it by forbidding a locked bootloader to boot with the dangerous boot modes. The first non-vulnerable bootloader version of Nexus 6 is 71.22 (released in the [November 2016 Android Security Bulletin](https://source.android.com/security/bulletin/2016-11-01.html)). The first non-vulnerable bootloader version of Nexus 6P is 03.64. The patch was released as part of the [January 2017 Android Security Bulletin](https://source.android.com/security/bulletin/2017-01-01.html).
Google rated `CVE-2016-6678` with Moderate severity and mitigated it by commit [`3f3c8a8`](https://android.googlesource.com/kernel/msm/+/3f3c8a8313ff7995498d6e794f67650c8ba8072d). The padding is now zeroed out so uninitialized bytes won't be leaked. The patch was released as part of the [October 2016 Android Security Bulletin](https://source.android.com/security/bulletin/2016-10-01.html).


[paper]: https://www.docdroid.net/dxKUj5c/attacking-nexus-6-6p-custom-bootmodes.pdf.html "paper"
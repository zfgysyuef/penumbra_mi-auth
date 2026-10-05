[[Antumbra]] provides a CLI module for interacting with the device in [[Download Agent|DA mode]].

## Basics

You'll need a [[Download Agent]] to be able to interact with the device.
If the device has DAA, you'll need the specific DA for your device.
If the device has SLA, you'll probably either need an engineering preloader or paid auth.

For Xiaomi devices that require a one-time BROM challenge, provide the matching AUTH file and
pass `--mi-auth` in CLI mode. Antumbra prints the `AgAA` BLOB in Base64 and hex and waits for
the 256-byte SIGN in either encoding. Connect the device in fresh BROM mode for each attempt.

```sh
antumbra --da DA.bin --auth auth_sv5.auth --mi-auth rpmb info
```

## RPMB

RPMB commands require DA extensions. `info` reports available regions and capacities;
`read` and `write` operate on 256-byte sectors. UFS devices may expose regions 0 through 3,
while eMMC uses region 0.

```sh
antumbra --da DA.bin rpmb info
antumbra --da DA.bin rpmb read --region 0 --start-sector 0 --num-sectors 1 rpmb.bin
antumbra --da DA.bin rpmb verify-derived --region 0
antumbra --da DA.bin rpmb write --region 0 --start-sector 0 --num-sectors 1 --key <64-hex-character-key> rpmb.bin
```

If `--num-sectors` is omitted, a read or write uses the remaining reported capacity. If the
device does not report capacity, specify `--num-sectors` explicitly. `write --key` and `auth`
accept a 32-byte key encoded as 64 hex characters.

`rpmb erase --region 0` writes zeroes to the entire region after authenticating the derived key.
`rpmb erase --all-regions` processes all reported regions. Erase is irreversible and has no
readback verification; it does not reset OTP keys or write counters.

## UFS firmware update (FFU)

Use `ufs-ffu` (alias `ffu`) with a raw UFS firmware image intended for the connected device.
The device must have UFS storage and an XML/V6 Download Agent that supports
`CMD:DEBUG:UFS` / `UPDATE-FIRMWARE`.

```sh
antumbra --da DA.bin ufs-ffu ufs_firmware.bin
```

The command streams the image to the DA and waits for its completion result. Afterward,
reconnect the device and verify its UFS firmware version using your device's diagnostics;
the DA result alone does not provide independent version verification.

## List all partitions

```sh
# Shows a list of all partitions on the device with start address and length
$ antumbra pgpt --da DA.bin
```

Aliases:

* `pgpt` => `gpt`

## Reading partitions

```sh
# Dump boot_a to boot.bin
$ antumbra read boot_a boot.bin --da DA.bin

# Same as read
$ antumbra upload boot_a boot.bin --da DA.bin

# Dumps boot_a to boot.bin through read flash (if read doesn't work)
$ antumbra read-flash boot_a boot.bin --da DA.bin

# Dump all partitions on the device except specified in skip
$ antumbra read-all --skip userdata,super --da DA.bin
```

Aliases:

* `read` => `r`, `upload`, `up`
* `read-flash` => `rf`
* `read-all` => `rl`


## Flashing partitions

```sh
# Writes boot.bin to boot_a
$ antumbra write boot_a boot.bin --da DA.bin

# Same as write
$ antumbra download boot_a boot.bin --da DA.bin

# Writes boot.bin to boot_a through write flash
$ antumbra write-flash boot_a boot.bin --da DA.bin
```

> [!WARNING]
> To flash `preloader` or `preloader_backup`, use `write` or `download`.
> If you use `write-flash`, make sure the preloader has the `UFS_BOOT` or `EMMC_BOOT` header, or the device will brick.

Aliases:

* `write` => `w`, `download`, `dl`
* `write-flash` => `wf`

## Erasing partitions

```sh
# Erases boot_a through erase flash command
$ antumbra erase boot_a --da DA.bin

# Erases boot_a through format command
$ antumbra format boot_a boot.bin --da DA.bin
```
Aliases:

* `erase` => `e`
* `format` => `ft`


## Rebooting or powering off the device

```sh
# Shutsdown the device
$ antumbra shutdown --da DA.bin

# Reboot the device to the specified mode
$ antumbra reboot <normal|home-screen|fastboot|meta|test> --da DA.bin
```

## Extensions commands

> [!WARNING]
> **THESE COMMANDS REQUIRE THE DEVICE TO BE ABLE TO LOAD [[DA Extensions|EXTENSIONS]], OR NOTHING WILL HAPPEN**
> If you don't see the `DA Extensions booted successfully` message, **these won't work**

### Unlock & relock bootloader

> [!WARNING]
> Not all OEMs can be unlocked with this command.
> All this does is unlock [[Seccfg|seccfg]]. Vendors like OnePlus or Xiaomi use RPMB lock.
> 

```sh
# Unlocks/Lock seccfg partition
$ antumbra seccfg <unlock|lock> --da DA.bin
```

### Read Memory

```sh
# Read memory from address 0x0 with length 0x20000, and save to brom.bin
$ antumbra peek 0x0 0x20000 brom.bin --da DA.bin
```

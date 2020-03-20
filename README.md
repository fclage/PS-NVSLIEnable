# PS-NVSLIEnable
Powershell script to automatically patch NVIDIA drivers to enable SLI on non-SLI cards (ex. GTX 1060)

## Usage
`.\Enable-SLI.ps1`

![Snapshot](https://i.ibb.co/523gV0g/PS-Nvidia-SLI-Enable-Script.png)


### SYNOPSIS
- Patches the Nvidia driver to enable SLI on all cards

### DESCRIPTION
- This script patches the Nvidia driver to enable SLI on all cards (including those without an SLI bridge, such as a GTX 1060 6GB)

### INPUTS
- SliDataFind             # find SLI patch location using the provided bytes such as "84:C0:75:05:0F:BA:6B"
- SliDataReplace          # patch values "C7:43:24:00:00:00:00"
- Originalfile            # original compressed driver file name, ex. "nvlddmkm.sy_"
- DontSearchSystem        # switch that will not search the system for the driver so you dont have to copy the source file
- EnableTestSigning       # Enables Windows driver test signing on boot

## Requires external tools in the "Tools" subfolder
- checksumfix "tools\ChecksumFix.exe"
- signtool "tools\signtool.exe"

### OUTPUTS
  Console log

### NOTES
- Version:        1.0
- Author:         Filipe Lage
- Creation Date:  2019-04-14
- Purpose/Change: This code is free for development and private use only
- Copyright:      (c)2019 Filipe Lage under Beerware License

`    "THE BEER-WARE LICENSE" (Revision 42 originally created by Poul-Henning Kamp - http://people.freebsd.org/~phk/):
    <fclage@gmail.com> wrote this file.  As long as you retain this notice you can do whatever you want with this stuff. 
    If we meet some day, and you think this stuff is worth it, you can buy me a beer in return.
    Thanks.
    Filipe Lage`

### EXAMPLES
- runs automated script with defaults
`Enable-SLI.ps1`

- Specify patch values and search for the right file in your system driverstore
`Enable-SLI.ps1 -searchInSystem -sliDataFind "84:C0:75:05:0F:BA:6B" -sliDataReplace "C7:43:24:00:00:00:00"`


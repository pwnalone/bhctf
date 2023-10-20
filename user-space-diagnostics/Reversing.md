# Reverse Engineering The UDS Server

Here, I'll walk you through, at a high level, how I analyzed the UDS server firmware image in
Ghidra. If you haven't already dumped the firmware and transfered it to your local machine, be sure
to do that now. Alternatively, you can import [image.bin](image.bin) into Ghidra to get the
unanalyzed binary. The pre-analyzed image can be found in [image.bin.gzf](image.bin.gzf).

To start, watch the following video from Block Harbor's YouTube channel. It goes through the initial
steps of creating a project in Ghidra, importing the firmware image, finding the `UDSHandler`
function (where most of our analysis will take place), and it even walks you through all of the
reversing necessary to solve _Security Access Level 3_.

[![UDS Security Access with
Ghidra](http://img.youtube.com/vi/cG4O8_nueUY/0.jpg)](https://www.youtube.com/watch?v=cG4O8_nueUY
"UDS Security Access with Ghidra")

Typically, one of the first things I do when I have to reverse engineer something is look for unique
strings in the binary that might lead me to some open source project where I can find at least the
partial source code. Opening up the _Defined Strings_ window, we can see that there are a lot of
strings, but most of them come from GNU Libc, and so are not interesting to us. Among the first
strings, however, you will notice some that begin with "UDS", and below those we find a few
challenge flags.

![Firmware Image Defined Strings](image-defined-strings.png)

Searching on Google for one of these strings brings us to this [GitHub
repository](https://github.com/driftregion/iso14229/tree/main), which appears to contain an
implementation of ISO-14229 (i.e. UDS). Looking through the source code in this repository we'll
notice that many of the strings we find in our binary can also be found in
[iso14229.c](https://github.com/driftregion/iso14229/blob/main/iso14229.c) and
[server.c](https://github.com/driftregion/iso14229/blob/main/examples/server.c). Therefore, it's
very likely that much of this code has been compiled into our firmware image, and we can use our
knowledge of the source to more quickly identify which functions do what and to rename/retype
variables to make the decompilation more readable. I won't describe this entire process because it's
very tedious and repetitive, but I'll cover one small example.

Let's say we wanted to identify which function in our binary is `main`. There's more than one way to
do this, but in this case we're going to try to identify it using the strings we see in the main
function in the repo's example server. In that function there are two calls to `printf` &ndash; one
that takes as an argument of `"server up, polling . . .\n"` and the other that takes the string,
`"server exiting\n"`. In the _Defined Strings_ window in Ghidra, we can search for either of these
strings and we'll be shown where it is located in the binary.

![Firmware Image Defined Strings Search](image-defined-strings-search.png)

At this location in the _Listing_ window, you can see that Ghidra has added annotations to show
cross-references (XREFs) to the string. You can jump to these XREFs by right clicking on the string
and going to `References -> Show References To Address`. This should open up a window with all the
references. Clicking on any them brings you to their location in both the _Listing_ and _Decompile_
windows.

![Firmware Image String Cross References](image-server-up-polling-string.png)

This particular string is only referenced from two locations inside a function that Ghidra failed to
find. Navigate to the beginning of the function in the _Listing_ window and hit the `F` key to
define it. In this function, you should see both strings that were present in the example server's
main function. While the decompilation does differ a bit here from what we see in the source code,
we can be fairly sure that this is indeed the same function. Any differences are likely to be
customizations made to the program by Block Harbor for their CTF and, as such, warrant extra
attention, since they could be key to understanding how to solve certain challenges that require
reversing the firmware.

During the course of reverse engineering the binary, we'll eventually come across the following
scary-looking function that seems to be important for solving _Security Access Level 5_. The first
thing we should notice in this function are the unique constants, `4357`, `0x9d2c5680`, and
`0xefc60000`. Additionally, the integers `624` and `227` are not too common and do appear in the
decompilation quite a bit. If we take these larger constants and put them into Google, we'll get a
bunch of results for MT19937, which is the most common variant of the Mersenne Twister PRNG. Thus,
without even having to reverse engineer this function, we were able to figure out what it does. If
you want to be extra sure, though, you can search on GitHub for C implementations of MT19937, and
see if the decompilation appears to match any of them. I did that and came across [this
implementation](https://github.com/ESultanik/mtwister/tree/master) that seems to be quite similar.

![Firmware Image PRNG Function](image-prng-function.png)

And that's basically everything I did to reverse engineer the UDS server image. I still had to do
some more reversing to solve _Custom Firmware_, but I just used the same process I already outlined
for you, above.

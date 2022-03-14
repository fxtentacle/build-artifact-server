# Build Artifact Server

This little app provides 
simple HTTPS object storage 
and a caching HTTPS proxy 
with automated letsencrypt certificates
and username & password authorization.

I use this with my
[Bazel Proxy Relay](https://github.com/fxtentacle/bazel-proxy-relay)
to easily (and securely) 
cache all Bazel dependencies - both direct and transient - 
on my own server so that I can rest assured 
that my builds will continue to work
even if some dependency changed their URL
or is having certificate problems (again).

I also use the POST support to store ZIP files
with precompiled dependencies.
For example, OpenCV is quite messy to set up,
but once you have the DLLs, LIBs, and header files
it's easy to ZIP them up and re-use them everywhere
using Bazel's http_archive.

In short, this artifact server helps me with 
re-using pre-compiled dependencies for static linking
and it makes my build process robust against 
failures on the public internet. 

BTW nowadays, you can even use
`vcpkg export opencv4 --zip`
to directly produce such ZIP files.
An official method for vcpkg to directly provide
pre-compiled packages has been in discussion for quite a while
but since I need most of my dependencies custom-compiled anyway - 
for example because I standardize the runtime library
and the OS libraries that my dependencies use -
I went ahead and built my own system for managing 
pre-compiled vcpkg packages.
And since I usually need this together with 
the cached Bazel dependencies,
that's why this is one HTTPS server to handle both.

For deployment, I use a cheap 5€ VPN. 
I mean basically everything with 1GB of RAM, 
a bit of storage and a public IP is fine.
But you do need the public IP 
so that you can setup a public domain for letsencrypt verification.
Otherwise, you'll need to use --self-signed-certificate
which is less secure.

This project comes with no warranty and no free support.
It works for me. If it works for you, great :)
If not, please fix things yourself ;)

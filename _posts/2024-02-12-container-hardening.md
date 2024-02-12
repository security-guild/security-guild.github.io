---
layout: post
title: Container Hardening using Distroless
date: 2024-02-12 08:00:00 +/-TTTT
categories: [hardening, container hardening]
tags: [
  oci, container, hardening, docker, security, lotl, lolbins, syft, grype, dive,
  distroless, rootless, sbom, vulnerability, scan
]
author: <vincent_remy>
---

<img
  alt="An Engineer analysing Docker containers"
  src="/assets/img/container-security-using-distroless.webp"
/>

## Living of the land

Before we dive into the technical details of Container Hardening I want to
address a few words on the concept of _Living of the land_ (LotL).

When an adversary gains a foothold in our system, they typically look for ways
to gain more access. A foothold means initial entry into the system and depending
on the vulnerability they can have various degrees of access. From a foothold
they might have access to some kind of shell and if not, they try to work their
way into a shell. Once an adversary gains a shell, they want to elevate privileges
so they can access sensitive parts of the system or pivot within the internal
network to other systems. Whatever they try to do from the foothold they will
leverage the concept of LotL.

Living of the land means that an adversary uses resources already available on
the target system for further exploitation. Resources can be any innocent looking
binary better known as LOLBins. We should be aware that every binary an adversary
gets it’s hands on is an opportunity for exploitation of the system. From working
from foothold to shell or from shell to privilege escalation, LotL will be
leveraged. This is even preferable, so we don’t make any “noise” and alert virus
scanners by using specialized tooling to exploit the system. Later in this
article I will give a simple demo to demonstrate this concept.

## Distroless

To counter LotL we should decrease the attack vector of our container image by
removing any component that is not necessary for running our application. This
is where the concept of Distroless container images comes in.

A Distro is an abbreviation of distribution which is a operating system build on
top of the Linux Kernel. Distroless means that all Distro specific components are
removed such as package managers, shells and a lot of common binaries used in
LotL attacks. With Distroless we significantly reduce the attack vector of our
containers making it much safer in two significant ways. It reduces the usage of
LotL attacks by removing LOLBins, it reduces the amount of possible vulnerable
packages and has an added benefit of reducing the overall image size.

Google provides
<a href="https://github.com/GoogleContainerTools/distroless" target="_blank">
Distroless Container Images</a> which we can use in a multi-stage build. We can
use multiple stages to configure dependencies and build our application. In the
last stage we can use a Distroless container image and copy only the binary,
libraries, and configuration over to the stage of our Distroless image. It will
be even better when we compile our application in a single self-contained binary.
While we do this, we also make the image rootless to increase the security inside
the container. Google provides the tag nonroot to for this purpose.

So now we know conceptually what a Distroless container image is, let’s build one!

## Building a Distroless container image

Before we can build a Distroless container image we need to have an app we can
run inside the container. For this demo we create a simple hello world app in
Golang. Create a file named `main.go` and add the code shown below.

```go
package main

import (
 "fmt"
 "net/http"
)

func HelloWorldHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello World!")
}

func main() {
	http.HandleFunc("/", HelloWorldHandler)
	http.ListenAndServe(":8008", nil)
}
```

This hello world app has a main function from which the app is initiated. In
this function a simple http server is created listening on port `8008`. When it
receives a GET request from `http://localhost:8008` it will be handled by the
function `HelloWorldHandler` and message `Hello World!` will be displayed.

In the same directory let's add a `Dockerfile` with the content below.

```Dockerfile
FROM golang:alpine3.1 as builder

WORKDIR /go/src/app

COPY main.go .

RUN go mod init github.com/security-guild/hello-world
RUN go mod tidy
RUN CGO_ENABLED=0 go build -o /go/bin/app

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /go/bin/app /

EXPOSE 8008

CMD ["/app"]
```

On line 1 the first stage is created and named `builder`. For this stage the
image is set to golang and specifically the tag `alpine3.1` is used so we pull
the Alpine version of Golang. The reason for this is that it is the only tag for
which the image doesn’t contain any vulnerable packages. On line 3 the working
directory is set to `/go/src/app` and the `main.go` file we just created is
copied from the host machine to the docker container image in this stage. After
this we initialize the Golang project (line 7), retrieve dependencies (line 8)
and build the `main.go` resulting in a binary in `/go/bin/app`. This binary is
self-contained using the `GO_ENABLED=0` environment variable. This means it
doesn’t depend on C libraries on the operating system.

On line 11 a final stage is created, a Distroless image is set and using the tag
`nonroot` we tell docker to pull the rootless version of this Distroless image
which further increases the security within the container. On line 13 we copy the
self-contained binary from the builder stage to the final stage. We expose port
`8008` so the application can receive incoming requests. On the last line we set
the `CMD` key and point it to our binary so it will run when the container starts.

Let’s build a new `hello-world` docker container image using the command shown
below. In this build command we also set the flag `--progress=plain` so we can
see a more verbose output from the build process. We also set the flag
`--no-cache` so it will build a fresh image instead of building from cache.

```sh
docker build --progress=plain --no-cache -t hello-world .
```

After building the new `hello-world` docker container image we can run and
configure it to listen on port `8008`.

```sh
docker run --name hello-world  -p 8008:8008 --rm hello-world
```

If everything went well we should now be able to visit
<a href="http://localhost:8008" target="_blank">http://localhost:8008</a>
and see the message `Hello World!` displayed in the browser.

As explained before a Distroless image doesn't contain a shell which could be
abused by an adversary. So, lets try to get a shell on our hardened container
`hello-world`.

```sh
 ~  >> docker exec -it hello-world sh
OCI runtime exec failed: exec failed: unable to start container process: exec: "sh": executable file not found in $PATH: unknown
 ~  >> docker exec -it hello-world /bin/sh
OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin/sh": stat /bin/sh: no such file or directory: unknown
 ~  >> docker exec -it hello-world bash
OCI runtime exec failed: exec failed: unable to start container process: exec: "bash": executable file not found in $PATH: unknown
 ~  >> docker exec -it hello-world /bin/bash
OCI runtime exec failed: exec failed: unable to start container process: exec: "/bin/bash": stat /bin/bash: no such file or directory: unknown
```

As shown in the terminal output it is not possible to get a shell from the
container because it was all removed by using the Distroless Container image.

## Generate a Software Bill of Materials using Syft

A Software Bill of Materials (SBoM) is a list of all components that makes up
a container image. In our case more specifically all packages used by our
container image. It is crucial to know what packages a container is running so
we can find out what the impact of LoTL is and if the packages contain
vulnerabilities.

To get an insight in the components of an image we can generate a Software Bill
of Materials (SBoM) using the CLI tool
<a href="https://github.com/anchore/syft" target="_blank">Syft</a>. Let's run
Syft against the container image `hello-world` we created in the previous
paragraph.

```sh
 ~  >> syft hello-world
 ✔ Loaded image                                                                                                                                   hello-world:latest   ✔ Parsed image                                                                              sha256:3016afdf4639e70fcacbb8852e21c0383361e78931bc4d553e358308b0dde8f7   ✔ Cataloged contents                                                                               ea99a900b62fc35c11f7620249aff0329f7f73887a9e0938cc6752891590f8cf
   ├── ✔ Packages                        [5 packages]
   ├── ✔ File digests                    [935 files]
   └── ✔ File metadata                   [935 locations]
NAME                                   VERSION          TYPE
base-files                             12.4+deb12u4     deb
github.com/security-guild/hello-world  (devel)          go-module
netbase                                6.4              deb
stdlib                                 go1.22.0         go-module
tzdata                                 2023c-5+deb12u1  deb
```

This gives a nice list of packages and their version numbers. Based on a SBoM we
can find out which packages are vulnerable and which packages contains LOLBins
that could be abused.

## Vulnerability scanning using Grype

<a href="https://github.com/anchore/grype" target="_blank">Grype</a> is a
vulnerability scanner for container images which can scan stand-alone, but it
can also take the SBoM we just created and show us the vulnerabilities. This can
be done by generating an SBoM using Syft, output it in JSON and pipe it to Grype
as shown in the terminal below.

```sh
 ~  >> syft hello-world -o json | grype
 ✔ Loaded image                                                                                                                                   hello-world:latest   ✔ Parsed image                                                                              sha256:3016afdf4639e70fcacbb8852e21c0383361e78931bc4d553e358308b0dde8f7   ✔ Cataloged contents                                                                               ea99a900b62fc35c11f7620249aff0329f7f73887a9e0938cc6752891590f8cf
   ├── ✔ Packages                        [5 packages]
   ├── ✔ File digests                    [935 files]
   └── ✔ File metadata                   [935 locations]
No vulnerabilities found
```

As show in the terminal Grype did not find a vulnerability in our Distroless
hello-world app. Now we know how to find vulnerabilities in container images it
is vital to understand that not all Distroless container images, even those
maintained by employees from big companies are secure by default. We should never
trust a Distroless image but always check with a container vulnerability scanner
such as Grype if the container image contains vulnerabilities. Let’s try to scan
a Distroless NodeJS container image with Grype.

```sh
 ~  >> grype gcr.io/distroless/nodejs18-debian12
 ✔ Vulnerability DB                [no update available]
 ✔ Loaded image                                                                                                           gcr.io/distroless/nodejs18-debian12:latest
 ✔ Parsed image                                                                              sha256:57f25fd864b3b2ecb2bc6ca8e38ca05d6e77af95e15053a7caca7bc3535a08c2
 ✔ Cataloged contents                                                                               bd2b4ead587530fa35e177efd583444d55b3da546ea2da1b5ae3126d082a23fa
   ├── ✔ Packages                        [8 packages]
   ├── ✔ File digests                    [1,237 files]
   └── ✔ File metadata                   [1,237 locations]
 ✔ Scanned for vulnerabilities     [22 vulnerability matches]
   ├── by severity: 1 critical, 2 high, 6 medium, 0 low, 12 negligible (1 unknown)
   └── by status:   3 fixed, 19 not-fixed, 0 ignored
NAME        INSTALLED         FIXED-IN        TYPE  VULNERABILITY     SEVERITY
libc6       2.36-9+deb12u3    2.36-9+deb12u4  deb   CVE-2023-6780     Critical
libc6       2.36-9+deb12u3    2.36-9+deb12u4  deb   CVE-2023-6779     High
libc6       2.36-9+deb12u3    2.36-9+deb12u4  deb   CVE-2023-6246     High
libc6       2.36-9+deb12u3                    deb   CVE-2019-9192     Negligible
libc6       2.36-9+deb12u3                    deb   CVE-2019-1010025  Negligible
libc6       2.36-9+deb12u3                    deb   CVE-2019-1010024  Negligible
libc6       2.36-9+deb12u3                    deb   CVE-2019-1010023  Negligible
libc6       2.36-9+deb12u3                    deb   CVE-2019-1010022  Negligible
libc6       2.36-9+deb12u3                    deb   CVE-2018-20796    Negligible
libc6       2.36-9+deb12u3                    deb   CVE-2010-4756     Negligible
libgcc-s1   12.2.0-14         (won't fix)     deb   CVE-2023-4039     Medium
libgcc-s1   12.2.0-14                         deb   CVE-2022-27943    Negligible
libgomp1    12.2.0-14         (won't fix)     deb   CVE-2023-4039     Medium
libgomp1    12.2.0-14                         deb   CVE-2022-27943    Negligible
libssl3     3.0.11-1~deb12u2  (won't fix)     deb   CVE-2024-0727     Medium
libssl3     3.0.11-1~deb12u2  (won't fix)     deb   CVE-2023-6129     Medium
libssl3     3.0.11-1~deb12u2  (won't fix)     deb   CVE-2023-5678     Medium
libssl3     3.0.11-1~deb12u2                  deb   CVE-2010-0928     Negligible
libssl3     3.0.11-1~deb12u2                  deb   CVE-2007-6755     Negligible
libssl3     3.0.11-1~deb12u2  (won't fix)     deb   CVE-2023-6237     Unknown
libstdc++6  12.2.0-14         (won't fix)     deb   CVE-2023-4039     Medium
libstdc++6  12.2.0-14                         deb   CVE-2022-27943    Negligible
```

As displayed in the terminal this container image might be Distroless but
contains many vulnerabilities! We can never just assume a container image is
safe by default whether it is Distroless or not. 

## Finding LOLBins in your container image using Dive

We already learned how to generate a SBoM from your container image. This is a
great starting point to identify LOLBins because we get a rough idea what to
look for. It would be Beter if we can inspect the container image and pinpoint
exactly what kind of LOLBins are available. For this task we can use a CLI tool
<a href="https://github.com/wagoodman/dive" target="_blank">Dive</a>.

Let's inspect container image `gcr.io/distroless/base:nonroot` with `dive` as
shown below.

```sh
dive gcr.io/distroless/base:nonroot
```

This opens an interactive interface with on the left side layers, layer details
and image details. On the right side we see the filesystem within the container
image. With the tab key we can toggle the focus between the left and right side.
When we are focussed on the left side, we can use the arrows up and down to move
through every layer in the container image. With this we can see how the
filesystem on the right side is impacted after each layer.

We can also search through the filesystem using ctrl-f and entering the search
query. This is great if we are searching for a specific LOLBin. When we are
focussed on the right side in the filesystem, we can move through the filesystem
with the arrow keys up and down. While we move down the file system, we can also
collapse directories with they space key, this is ideal when we want to skip huge directories. Finaly we can hide/show all unmodified files with ctrl-u so we can
see all modified files. In the following screencast a little demo is given to
get an impression of how Dive looks like.

<img alt="A demo of the CLI tool Dive" src="/assets/img/dive-demo.gif" />

When searching for LOLBins we should look in the directories commonly used in
Linux to store binaries as shown in the list below.

```sh
/bin # Essential command binaries that are required for system booting and repairing.
/sbin # System binaries, often used by the system administrator for system maintenance and configuration.
/usr/bin # Non-essential command binaries for all users.
/usr/sbin # Non-essential system binaries for system administrators.
/usr/local/bin # Binaries installed by the system administrator or from third-party software.
/usr/local/sbin # System binaries installed locally by the system administrator.
/opt/ # Optional application software packages.
/snap/bin # Binaries installed via snap packages.
/home/<username>/.local/bin # Binaries installed locally by a user in their home directory.
```

When we find LOLBins in our container image we can analyse the impact it will
have by using the website
<a href="https://gtfobins.github.io" target="_blank">GTFOBins</a>. In this
website we can enter the name of the binary we found and see what the impact is
regarding LotL attacks. Of course, we should strip out any binary that is not
necessary for running our applications. But if we need it we should be aware
what the potential for usage in LotL attacks and how to mitigate undesired
behaviour.

## Distroless "shell" access using LotL Binary OpenSSL

We have learned how to apply hardening by leveraging Distroless and rootless
container images. We also learned how Distroless container images can still
contain vulnerable packages or LOLBins.

In this scenario we created a Distroless and Rootless container image. We did
scan our container image with Grype and we found no vulnerable packages. But we
do have a LOLBin available in our hardened container. Imagine an adversary manage
to get a foothold through a vulnerability in the application which is running in
the container. From this foothold they try to get shell access, but no shell can
be found as demonstrated in previous chapters. But there is still a way in so
let’s discover how this exactly works.

From our perspective we can start by generating a SBoM to get an idea where to
look for. 

```sh
 ~  >> syft gcr.io/distroless/base:nonroot
 ✔ Loaded image                                                                                                                       gcr.io/distroless/base:nonroot   ✔ Parsed image                                                                              sha256:50aae94a9dc9480e122bc8a2abf3ef3da0d566f64764069d0158a05942bb5789   ✔ Cataloged contents                                                                               0129b5d2b2aa71d6ecde4816a12f7dccc55ed9febfc135cc44226ec6fa4f18bd
   ├── ✔ Packages                        [6 packages]
   ├── ✔ File digests                    [1,585 files]
   └── ✔ File metadata                   [1,585 locations]
NAME        VERSION           TYPE
base-files  11.1+deb11u8      deb
libc6       2.31-13+deb11u7   deb
libssl1.1   1.1.1w-0+deb11u1  deb
netbase     6.3               deb
openssl     1.1.1w-0+deb11u1  deb
tzdata      2021a-1+deb11u11  deb
```

In the SBoM we find the package OpenSSL which can be found in many projects.
OpenSSL is an example of a LOLBin which can be abused. An adversary can enumerate
the application and come up with the conclusion that it is highly likely that
OpenSSL is needed for the application to run and tries it out.

As shown in the terminal we should not have access to a shell in our Distroless
container, but OpenSSL can provide us with some kind of shell.

```sh
 ~  >> docker run --rm -it gcr.io/distroless/base:nonroot openssl
OpenSSL>
```

This shell can be used to retrieve files which should not be accessible. For
example, we could retrieve all users on the system. This in combination with
retrieving the `/etc/shadow` file could be enough to brute force the credentials
for each user in the `/etc/passwd` file.

```sh
 ~  >> docker run --rm -it gcr.io/distroless/base:nonroot openssl enc -in /etc/passwd
root:x:0:0:root:/root:/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/sbin/nologin
nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin
```

We could also abuse this to retrieve environment variables running in processes
on the container. Many developers pass credentials from the container environment
to the application using environment variables. In the example below we retrieved environment variables running in a process with process ID 1. Luckly for us this
time no sensitive information was found.

```sh
 ~  >> docker run --rm -it gcr.io/distroless/base:nonroot openssl enc -in /proc/1/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=d82e105b7d6e
TERM=xterm
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
HOME=/home/nonroot
```

A final example is how an adversary could abuse this for enumeration purposes,
in this case we can determine from the outside with what kind of system we are
dealing with.

```sh
 ~  >> docker run --rm -it gcr.io/distroless/base:nonroot openssl enc -in /usr/lib/os-release
PRETTY_NAME="Distroless"
NAME="Debian GNU/Linux"
ID="debian"
VERSION_ID="11"
VERSION="Debian GNU/Linux 11 (bullseye)"
HOME_URL="https://github.com/GoogleContainerTools/distroless"
SUPPORT_URL="https://github.com/GoogleContainerTools/distroless/blob/master/README.md"
BUG_REPORT_URL="https://github.com/GoogleContainerTools/distroless/issues/new"
```

OpenSSL has much more capabilities for further exploitation including writing to
files and the usage of OpenSSL reverse shells as can be found in GTFOBins.

This is just one example of LotL but the point is that any binary could be
abused when a foothold is gained.

## Conclusion

When an application running in a container is breached through a vulnerability or misconfiguration and a foothold is gained into the container environment, we can
make the foothold useless by applying multiple levels of hardening. In this
article we just learned how to apply the concept of Distroless container images
and how to recognize the risk when implementing this layer of hardening.

This is just one part of container hardening and there are many more layers of
hardening we can apply but this will be subject of upcoming articles.
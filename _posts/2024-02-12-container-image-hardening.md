---
layout: post
title: Container Image Hardening
date: 2024-02-15 08:00:00 +/-TTTT
categories: [hardening, container hardening]
tags: [
  oci, container, hardening, docker, security, lotl, lolbins, syft, grype, dive,
  distroless, rootless, sbom, vulnerability, scan
]
author: vincent_remy
image: https://security-guild.github.io/assets/img/container-security-using-distroless.webp
---

<img
  alt="An Engineer analysing Docker containers"
  src="/assets/img/container-security-using-distroless.webp"
/>

Container hardening is all the measures taken to mitigate vulnerabilities and
abuse of weaknesses of containerization. Not only the measures taken in the
container image itself but all components that make it possible to run a
container as well.

Containerization consist of many layers of technology working together. From a
hardening perspective this means that we might need to apply multiple levels of
hardening to cover most of the attack vectors.

It will take several articles to cover most of the layers of hardening we can
apply. For this article we focus on the container image specifically from the
perspective of a Developer. We want to develop a container image which is a
secure foundation to run our application in. For this we first need to learn
container image analysis so we can identify vulnerabilities and weaknesses.
When we have gained insight in this we will learn how to apply a layer of
hardening to mitigate weaknesses.

## Attack vector explained

When we run containers in production it contains services and on top of it we
run an application. For example, we ca run Nginx, PHP-FPM and MySQL
containers with on top of it a Wordpress Blog.

In this situation many attack vectors can occur depending on the vulnerabilities
and misconfigurations that can be found. A possible but pretty simple attack
vector could look like the following.

1. A Wordpress Plugin is outdated and contains a Blind SQL Injection
2. Through this Blind SQL Injection user password hashes are retrieved
3. Wordpress password hashes are bruteforced and the administrator password is
   found
4. Hacker login on the Wordpress Dashboard using the bruteforced password
5. Hacker upload and enable a reverse-shell disguised as a Wordpress Plugin
6. The uploaded Wordpress Plugin is executed and a reverse-shell is captured on
   the attackers machine using Netcat.

There are many attack paths possible much more creative than the example given.
But this is where our story starts regarding container hardening.

From the foothold commands can be send to a container and in our example
commands where send to execute a reverse-shell which establish terminal access
for the attacker into the container environment where our application is running
in.

From this point in the attack there are many oppertunities to further exploit
the system which is out of scope for this article. But the main areas for
exploitation are vulnerable packages, binaries and misconfigurations. We will
not discuss the subject of misconfigurations because it deserves a dedicated
article. We will focus on vulnerable packags and and binaries that can be abused.

Our goal is to make this foothold useless by removing all vulnerabilities and
weaknesses which could be exploited.

## Identify vulnerable packages

if we want to find out which packages are vulnerable in a container we should
atleast know how to get a list of packages. This list of packages is better known
as a Software Bill of Materials (SBoM). To generate a SBoM from a container we
can use CLI tool <a href="https://github.com/anchore/syft" target="_blank">Syft</a>.
So let's run Syft to generate a SBoM fronm a Distroless container image.

```sh
syft gcr.io/distroless/static-debian12:nonroot
```

<img alt="Syft SBoM generation" src="/assets/img/syft-sbom-generation.gif" />

This gives a nice list of packages and their version numbers. We can use this
SBoM to manually find weaknesses which we will discuss in further paragraphs. We
can also give this list to a container vulnerability scanner to find out which
packages are vulnerable. For this container vulnerability scanner
<a href="https://github.com/anchore/grype" target="_blank">Grype</a> can be used.
This scanner can take a SBoM and find based on this vulnerabilities but it can
also enumerate packages all by itself and find the vulnerabilities.

Let's first feed Grype an SBoM by using the same command as before but use the
`-o` flag to output in JSON format so it can be piped to Grype.

```sh
syft gcr.io/distroless/static-debian12:nonroot -o json | grype
```

<img
  alt="Grype scan with Syft generated SBoM"
  src="/assets/img/syft-grype-sbom.gif"
/>

As shown in the terminal Grype did not find a vulnerability in our Distroless
container image. Now let's try to scan an image just with Grype alone.

```sh
grype bitnami/minideb:latest
```

<img alt="Grype image scan" src="/assets/img/grype-image-scan.gif" />


As displayed in the terminal this minideb container image has many
vulnerabilities even with the latest tag. What we can learn from this is that we
should never trust but verify if images are vulnerable, even from well respected
sources. When we encounter vulnerable images we should update the container
images. If the maintainers of the image do not maintain their images as expected
we should consider to move to beter maintained images or build and maintain the
images ourselves.

## Living of the land and LOLBins

Living of the land means that an attacker uses resources already available on
the target system for further exploitation. Resources can be any innocent looking
binary better known as a LOLBin. We should be aware that every binary an attacker
gets it’s hands on is an opportunity for exploitation of the system. From working
from foothold to shell or from shell to privilege escalation, LotL will be
leveraged. This is even preferable, so we don’t make any “noise” and alert virus
scanners by using specialized tooling to exploit the system which is more easily
detected.

## Mitigate LOLBins using Distroless

To counter LOLBins we should remove any binary that could be abused and is not
neccessary for running our application. This is where the concept of Distroless
container images comes in.

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
While we do this, we can also make the image rootless to increase the security
inside the container. Google provides the tag nonroot to for this purpose.

## A LOLBin demo with OpenSSL

<img alt="A LOLBin demo with OpenSSL" src="/assets/img/lolbin.gif" />

In the previous paragraph we explained how Distroless images can be used as a
layer of hardening against LOLBins. But before we build on top of a Distroless
container image we should understand an important fact. Even Distroless images
with the tag `latest` can contain vulnerable packages and LOLBins. As said
before we should always verify container images we pull from online sources.

For this demo i use a Distroless and Rootless container image and explore the
impact of a single LOLBin, in this case an OpenSSL LOLBin. As mentioned before
a Distroless image doesn't contain shells. But our OpenSSL LOLBin contains a
shell we could abuse.

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
to the application using environment variables. In the example below we retrieved
environment variables running in a process with process ID 1. Luckly for us this
time no sensitive information was found.

```sh
 ~  >> docker run --rm -it gcr.io/distroless/base:nonroot openssl enc -in /proc/1/environ
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
HOSTNAME=d82e105b7d6e
TERM=xterm
SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
HOME=/home/nonroot
```

A final example is how an attacker could abuse this for enumeration purposes,
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
files and the usage of OpenSSL reverse shells.

This is just one example of LotL but the point is that any binary could be
abused when a foothold is gained.

## Identify LOLBins and research the impact

In the previous chapter we discovered the impact of a single LOLBin even in a
Distroless container image. To find LOLBins and research their impact we can
start with generating an SBOM. This gives a good idea of where to look for in a
container image. It would be Beter if we can inspect the container image and
pinpoint exactly what kind of LOLBins are available. For this task we can use a
CLI tool <a href="https://github.com/wagoodman/dive" target="_blank">Dive</a>.
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
collapse directories with they space key, this is ideal when we want to skip huge
directories. Finaly we can hide/show all unmodified files with ctrl-u so we can
see all modified files. In the following terminal a little demo is given to
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

## Building a Distroless container image

Now we know what a Distroless container image and how to identify it's weak
spots we can finally build one.

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
abused by an attacker. So, lets try to get a shell on our hardened container
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

## Conclusion

In this article we learned how to apply container image analysis to identify
vulnerable packages and LOLbins. We learned how to apply Distroless as layer of
hardening against LOLBins and find out what the impact of LOLBins are. We can
now build a more secure foundation to run our applications in.

In upcoming articles we will explore more layers of hardening we can apply to
further enhance container security.
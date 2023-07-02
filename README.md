# INET (Distributed) Denial of Service models for ID2T
This repository contains the models and application code for generating realistic Denial of Service attacks in the context of [ID2T](https://github.com/tklab-tud/ID2T).

This project is part of the thesis work conducted at DTU, for the achievement of the degree of MSc in Computer Science and Engineering.

## Installation

To install the extension, there are two options:

1. Manual installation:    
    - Import the `id2t-omnetpp` project into OMNeT++ and compile it along with its dependencies.
    - Create a `lib/` folder in the `id2t-omnetpp` project root.
    - Place the compiled dynamic libraries inside the `lib/` folder.
    - Copy the `id2t-omnetpp` project folder to the `resources/` directory of the ID2T project.

2. Precompiled release installation (simpler and more immediate):
    - Download the precompiled release from the repository.
    - Copy the downloaded release to the `resources/` directory of the ID2T project.
    - Launch ID2T to start using the extension.

3. Undocumented option:
    - Download the Docker image.
    - Use `docker load < id2t-omnetpp-docker.tar` to load the image.
    - Use `docker run -ti --user id2t -w /home/id2t/ID2T -v $(pwd)/:/home/id2t/ID2T/pcaps id2t-omnetpp:1.0.0 /bin/zsh` to:
	    - Run and attach to `/bin/zsh` in a new container based on `id2t-omnetpp` image.
	    - As a low privilege user called `id2t`, from the working directory `/home/id2t/ID2T`.
	    - With a volume that maps the host current directory `$(pwd)` to container's `/home/id2t/ID2T/pcaps` folder.

Note: currently, compiled libraries are only available for linux-amd64.

## Usage
The extension is meant to be used within ID2T. Refer to the project [README](https://github.com/tklab-tud/ID2T/blob/feature/omnet-ddos/README.md) for usage, specifically to the [feature/omnet-ddos](https://github.com/tklab-tud/ID2T/tree/feature/omnet-ddos) branch.

## Modeled attacks
Currently, the following DoS attacks are supported: UDP Flood, DNS Amplification and Slowloris.

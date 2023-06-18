# INET DDoS models for ID2T

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
    - Use `docker run -ti --user id2t -w /home/id2t/ID2T -v $(pwd)/:/home/id2t/ID2T/pcaps id2t-omnetpp:1.0.4 /bin/zsh` to:
	    - Run and attach to `/bin/zsh` in a new container based on `id2t-omnetpp` image.
	    - As a low privilege user called `id2t`, from the working directory `/home/id2t/ID2T`.
	    - With a volume that maps the host current directory `$(pwd)` to container's `/home/id2t/ID2T/pcaps` folder.

Note: at this moment, only linux-amd64 is supported.

## Usage
## Results

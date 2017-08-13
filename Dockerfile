FROM jgoerzen/debian-base-standard
LABEL Description="This image is used to test the c tor2web proxy" Version="0.1"
RUN apt-get -yq update && \
    apt-get -yq --no-install-suggests --no-install-recommends \
        --allow-downgrades --allow-remove-essential \
        --allow-change-held-packages install \
            build-essential automake autoconf-archive libgnutls28-dev \
            libio-socket-socks-perl libproc-daemon-perl libipc-run-perl \
            libcommon-sense-perl libhttp-daemon-perl libio-socket-ssl-perl \
            strace ltrace valgrind doxygen curl git && \
    curl --remote-name \
  http://ftp.us.debian.org/debian/pool/main/l/lcov/lcov_1.11-3_all.deb && \
    dpkg -i lcov_1.11-3_all.deb && \
    echo "lcov hold" | dpkg --set-selections && \
    apt-get -yq install && apt-get -yq dist-upgrade && apt-get clean && \
    rm -rf /var/lib/apt/lists/* && mkdir -p /usr/src/github
COPY . /usr/src/github/tor2web
RUN cd /usr/src/github/tor2web; chmod -R g-w .; t/bin/root-setup.sh; aclocal -W all && automake -v -W all --add-missing && autoconf -v -W all
RUN cd /usr/src/github/tor2web; ./configure --enable-code-coverage
#RUN cd /usr/src/github/tor2web; ./configure

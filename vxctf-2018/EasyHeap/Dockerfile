FROM ubuntu:16.04

#installation
RUN apt-get update && apt-get upgrade -y 
RUN apt-get install -y socat build-essential

#user
RUN adduser --disabled-password --gecos '' vxctf_heap
RUN chown -R root:vxctf_heap /home/vxctf_heap/
RUN chmod 750 /home/vxctf_heap
RUN chmod 740 /usr/bin/top
RUN chmod 740 /bin/ps
RUN chmod 740 /usr/bin/pgrep
RUN export TERM=xterm

WORKDIR /home/vxctf_heap/

COPY vxctf_heap /home/vxctf_heap
COPY flag /home/vxctf_heap

RUN chown root:vxctf_heap /home/vxctf_heap/flag
RUN chmod 440 /home/vxctf_heap/flag

RUN chown root:vxctf_heap /home/vxctf_heap/vxctf_heap
RUN chmod 750 /home/vxctf_heap/vxctf_heap


RUN strip -s vxctf_heap

EXPOSE 8026
CMD su vxctf_heap -c "socat -T10 TCP-LISTEN:8026,reuseaddr,fork EXEC:/home/vxctf_heap/vxctf_heap"
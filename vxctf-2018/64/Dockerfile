FROM debian

#installation
RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y socat build-essential

#user
RUN adduser --disabled-password --gecos '' orange
RUN chown -R root:orange /home/orange/
RUN chmod 750 /home/orange
#RUN chmod 740 /usr/bin/top
#RUN chmod 740 /bin/ps
#RUN chmod 740 /usr/bin/pgrep
RUN export TERM=xterm

WORKDIR /home/orange/

COPY 64 /home/orange
COPY flag /home/orange

RUN chown root:orange /home/orange/flag
RUN chmod 440 /home/orange/flag

RUN chown root:orange /home/orange/64
RUN chmod 750 /home/orange/64


RUN strip -s 64

EXPOSE 8026
CMD su orange -c "socat -T10 TCP-LISTEN:8026,reuseaddr,fork EXEC:/home/orange/64"
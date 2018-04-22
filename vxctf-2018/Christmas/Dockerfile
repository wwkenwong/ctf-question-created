FROM debian:oldstable


#installation
RUN apt-get update && apt-get upgrade -y 
RUN apt-get install -y socat build-essential


#user
RUN adduser --disabled-password --gecos '' rop
RUN chown -R root:rop /home/rop/
RUN chmod 750 /home/rop
RUN chmod 740 /usr/bin/top
RUN chmod 740 /bin/ps
RUN chmod 740 /usr/bin/pgrep
RUN export TERM=xterm

WORKDIR /home/rop/

COPY rop /home/rop
COPY flag /home/rop

RUN chown root:rop /home/rop/flag
RUN chmod 440 /home/rop/flag

RUN chown root:rop /home/rop/rop
RUN chmod 750 /home/rop/rop


RUN strip -s rop

EXPOSE 8026
CMD su rop -c "socat -T10 TCP-LISTEN:8026,reuseaddr,fork EXEC:/home/rop/rop"
FROM ubuntu:16.04

#installation
RUN apt-get update && apt-get upgrade -y 
RUN apt-get install -y socat build-essential

#user
RUN adduser --disabled-password --gecos '' sanity
RUN chown -R root:sanity /home/sanity/
RUN chmod 750 /home/sanity
RUN chmod 740 /usr/bin/top
RUN chmod 740 /bin/ps
RUN chmod 740 /usr/bin/pgrep
RUN export TERM=xterm

WORKDIR /home/sanity/

COPY sanity /home/sanity
COPY flag /home/sanity

RUN chown root:sanity /home/sanity/flag
RUN chmod 440 /home/sanity/flag

RUN chown root:sanity /home/sanity/sanity
RUN chmod 750 /home/sanity/sanity



RUN strip -s sanity

EXPOSE 8026
CMD su sanity -c "socat -T10 TCP-LISTEN:8026,reuseaddr,fork EXEC:/home/sanity/sanity"

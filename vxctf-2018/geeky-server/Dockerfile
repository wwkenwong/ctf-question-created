FROM ubuntu:16.04


######https://drive.google.com/open?id=1tXgQ6zMYQTI1WnYvq73CHdM6i4ln3bqa
######libc larger than 15 mb, need download from here
COPY libc-2.24.so /lib/x86_64-linux-gnu/libc-2.23.so
RUN chmod a+x /lib/x86_64-linux-gnu/libc-2.23.so


#installation
RUN apt-get update && apt-get upgrade -y 
RUN apt-get install -y socat build-essential


#user
RUN adduser --disabled-password --gecos '' geek
RUN chown -R root:geek /home/geek/
RUN chmod 750 /home/geek
RUN chmod 740 /usr/bin/top
RUN chmod 740 /bin/ps
RUN chmod 740 /usr/bin/pgrep
RUN export TERM=xterm

WORKDIR /home/geek/

COPY geek /home/geek
COPY flag /home/geek

RUN chown root:geek /home/geek/flag
RUN chmod 440 /home/geek/flag

RUN chown root:geek /home/geek/geek
RUN chmod 750 /home/geek/geek


RUN strip -s geek

EXPOSE 8026
CMD su geek -c "socat -T10 TCP-LISTEN:8026,reuseaddr,fork EXEC:/home/geek/geek"


FROM zeek/zeek:7.1
# FROM zeek/zeek:6.1
# FROM zeek/zeek:5.1
# FROM zeek/zeek:latest
ARG DEBIAN_FRONTEND=noninteractive

RUN apt update
RUN apt install libpcap-dev g++ cmake -y
RUN apt install wget nano


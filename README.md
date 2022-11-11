# 1m-block
## Objective
* Block one million of harmful hosts
## Component
* ip : IP struct
* ipv4hdr : IPv4 Header Struct
* tcphdr : TCP Header Struct
* 1m-block : check packet and decide accept/drop
## Requirements
* Consider 1 million sites in the zip file as harmful and implement the logic determining if they exist in the list by checking the host value after "Host:" in HTTP Reqeust
* The implementation of logic focuses on memory and search speed
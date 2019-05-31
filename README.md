Monitoring IP-based networks
============================

This repository provides code examples to the article [Monitoring IP-based networks](https://medium.com/@florianlehner/monitoring-ip-based-networks-59c1ec7bf616).

Demo
----

You can test the concept implementations with the provided docker file.

```bash
$ docker build  -f Dockerfile .
$ docker run --cap-add=NET_ADMIN -it monitoringdemo
```

# FFanalyse
Fast-Flux Analyse

# Theoretical background 

A theoretical background is essential to explain why virtual police stations lack preparation. At the dawn of the Internet, users accessed a server via IP addresses. IP addresses are also known as Internet Protocol Addresses.
To simplify human-machine interaction, domains replaced IP addresses. In contemporary times, users type the domain into the browser, like _www.example.com_. This makes the experience more accessible and user-friendly.
The DNS (Domain Name System) protocol determines the IP address of the web server. It does this when someone types a domain like www.example.com into a browser. The web server (_www_) associates the IP address. In this case, it’s for the domain _example.com_.
This search proceeds recursively between servers at different levels. It continues until one provides the requested address. When the server receives a request, it searches its registry for the mapping. If it can't find one, it tells you what server to use for the domain.

The DNS protocol aims to provide a mapping between domain names and IP addresses. This functionality allows a server with just one IP address to have several domains. This is also called _domain aliasing_. Too, DNS makes it possible to access a single web server via different domains. 
Figure 1 illustrates this. 
Furthermore, the DNS protocol allows distributing the same domain among different servers.
If one of these servers fails, the others continue to offer the same service on the World Wide Web. The DNS protocol enables _n:m_ mapping between IP addresses and domains. 1 (one) IP address can be linked to _n_ domains and 1 (domain) can be linked to _m_ IP addresses. The DNS protocol allows for mirroring the same content on different servers. Storing the same content on several servers is essential for high-demand, high-volume data. It's an aspect of fault tolerance. 
If one server stops working, the others will continue to provide the same service on the World Wide Web. Load balancing is also an advantage. If a server becomes overloaded, the servers can balance the workload. Response times are also reduced. The system chooses the server closest to the request by default. This optimizes the service's response time.
We developed scripts to examine the number of servers at each police station.

![Illustrated operation of the DNS protocol](https://github.com/DejavuForensics/FFanalyse/blob/main/Images/1.png)
**Figure 1**: Illustrated operation of the DNS protocol. 

## Follow the instructions:
### Installation and handling of auxiliary libraries:

-	In the console, install the _dnspython_ library responsible for requesting DNS servers.
```  
pip install dnspython
```

-	In the console, install the _pygeoip_ library responsible for detecting the geolocation of an IP address..
```  
pip install pygeoip
```

-	Install the _mgrs_ library in the console. It detects the geolocation of an IP address using MGRS, the Military Grid Reference System. MGRS was developed by the NATO military. The benefit of MGRS is that it allows grid designation of **a geographic point below one square metre**.
```  
pip install mgrs
```

-	Install the _pytz_ library in the console. The library calculates the time zone of a given region where the IP address is located.
```  
pip install pytz
```

-	In the console, install the _berserker_resolver_ library. It determines all the IP addresses linked to a given domain.
```  
pip install berserker_resolver
```

### Parameter to use the authorial script.

We developed scripts to examine the number of servers at each police station in Brazilian Northeast. 

```
python FFanalyse.py -d google.com 
```

## Feature Description for Fast-Flux

The extraction should catalogue the number of IP addresses linked to the audited domain. Server mirroring is a practice used by both legitimate and illegitimate servers. This observation is particularly relevant. Distributed denial of service attacks can coordinate multiple servers in a synchronized manner. This coordination can be exploited to promote industrial sabotage. It poses a significant threat to the integrity and operation of the target server. A thorough understanding of IP address characteristics contributes to cyber security. It also highlights the need for preventative strategies to counter potential coordinated attacks.

### Domain with multiple servers

Figure 2 shows that a domain can be linked to _n_ multiple servers with the same replicated content. 

![A domain can be linked to _n_ different servers with the same replicated content](https://github.com/DejavuForensics/FFanalyse/blob/main/Images/2.png)

</center>

**Figure 2**: A domain can be linked to _n_ different servers with the same replicated content. 

### TTL(Time to Live)

TTL (Time to Live) is the number of hops packets can make in a computer network before being discarded. It refers to the number of jumps between machines. The TTL value and service efficiency have an inverse relationship. This is an important consideration. A higher TTL indicates that packets may take longer to travel across the network. This suggests a possible slowdown in the service. This slowness can be attributed to the absence of effective fault tolerance mechanisms. Understanding the impact of TTL provides insights into the importance of proactive measures. This is to optimize the performance and resilience of the network infrastructure. Services concentrated on a single IP address can have a high TTL. Consequently, they can have a slow response time.

### Geolocalisation of IP address(es)

We are working on geolocalising IP addresses. This script provides information about IP addresses. It includes mapping for 250 countries. It also includes latitude, longitude and other geoinformation related to an IP address.

### Greenwich Meridian Timezone

The term "Timezone" refers to the geographical location of the IP address's time zone. In this context, GMT (Greenwich Meridian Time)  acts as a central reference point. It represents the zero base value. The assignment of values to each time zone is determined by its distance from GMT.
Figure 3 illustrates the Greenwich Meridian timezones. 

![Illustration of the Greenwich Meridian timezones](https://github.com/DejavuForensics/FFanalyse/blob/main/Images/3.png)

</center>

**Figure 3**: Illustration of the Greenwich Meridian timezones.

### UTM (Universal Transverse Mercator)

The UTM (Universal Transverse Mercator) c offers an alternative to the traditional ellipsoidal grid model of the Earth. This system is designed to simplify cartographic representation. It divides the Earth's surface into sixty distinct zones. Each zone is identified by a numerical value indicating its position along the globe. It is followed by an alphabetical character that provides an additional reference. This zonal approach to the UTM simplifies spatial representation. The particularities and functionalities of the UTM system highlight its relevance in practical applications. These applications demand precision and efficiency in spatial representation and localisation.

Figure 4 illustrates the UTM timezones. 

![Illustration of the UTM timezones](https://github.com/DejavuForensics/FFanalyse/blob/main/Images/4.png)

</center>

**Figure 4**: Illustration of the UTM timezones.

### MGRS

The MGRS (Military Grid Reference System) was designed to establish an efficient standard for geo-coordination. The NATO military developed the MGRS. It has a significant benefit. It can assign a grid to a geographical point with an accuracy of less than one square metre.
Figure 5 illustrates the MGRS coordinates. 

![Illustration of the MGRS coordinates](https://github.com/DejavuForensics/FFanalyse/blob/main/Images/5.png)

</center>

**Figure 5**: Illustration of the MGRS coordinates.


## Feature Description for DGA

DGA, or Domain Generation Algorithm, is an algorithm used in cybersecurity and malware. It generates a large number of domain names dynamically. Malware, like botnets, often uses this approach to evade detection by security solutions. DGA creates domain names in a pseudo-random or deterministic way. It's usually based on mathematical algorithms or specific seeds. The domain is generated dynamically. Consequently, it will not be on any firewall or other security mechanism block lists.
Figure 6 illustrates domain generated by DGA. 
These domains are used in the Torpig, Kraken and Conficker-C botnet.

![Torpig, Kraken and Conficker-C are botnets with DGA](https://github.com/DejavuForensics/FFanalyse/blob/main/Images/6.png)

</center>

**Figure 6**: Torpig, Kraken and Conficker-C are botnets with DGA.

Detecting malicious activity using DGA is a constant challenge in the cybersecurity field. Modern solutions aim to identify suspicious patterns or behaviors linked to these algorithms. 
This script extracts domain name features. It studies if DGA was used in their creation.
There are basic features of domains generated by a DGA.
Entropy represents the degree of randomness of information.

-	Number of domain levels;
- Size of the 2LD;
- Number of distinct characters in the 2LD;
- Number of digits in the 2LD;
- Entropy of the 2LD;
- Size of the 3LD;
- Number of distinct characters in 3LD;
- Number of digits in the 3LD;
- Entropy of the 3LD.


# Anubis
A cache backed lookup service for IP Addresses leveraging AbuseIPDB, RiskIQ, VirusTotal, and HybridAnalysis

## Installation
 `go get install -u github.com/louisbarrett/anubis`

## CLI Options
```
Usage of anubis
  -cli
        CLI Mode
  -dev
        Internal development
  -ip string
        IP Address to lookup
  -json
        Output in JSON
  -lambda
        Toggle lambda execution
  -log
        Enable debug output
```

## Environment Variables

### Required
```
ABUSEDBSECRET - AbuseIP DB Secret
HAKEY - HybridAnalysis API Key
HASECRET - HybridAnalysis API Secret
PTUSER - PassiveTotal API User
PTAPIKEY - PassiveTotal API Key
VTAPIKEY - VirusTotal API Key
```
### Optional

```
REDIS_CLUSTER - Redis cluster URL
```

## Sample Output

```
$ ./anubis.exe -cli -ip 120.79.27.209 

IP Address: 120.79.27.209
AS: CNNIC IPAS CONFEDERATION - 37963
Domain: aliyun.com
Country: CN
Usage: Data Center/Web Hosting/Transit

Risk Rating: High 105
Compromised: false
AbuseDB Confidence Score: 55
VirusTotal Malicious Score: 50
VirusTotal Suspicious Score: 0
```

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/Jeffail/gabs/v2"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/go-redis/redis/v7"
)

const (
	enrichment           = "https://api.passivetotal.org/v2/enrichment"
	dnsPassive           = "https://api.passivetotal.org/v2/dns/passive"
	whoisURL             = "https://api.passivetotal.org/v2/whois"
	hybridAnalyisBaseURL = "https://www.hybrid-analysis.com/api/v2/search/terms"
)

var (
	redisCluster     = os.Getenv("REDIS_CLUSTER")
	recordExpiration = time.Now()
	// BRUH
	abuseDBKey     = os.Getenv("ABUSEDBSECRET") //
	abuseDBBaseURL = "https://www.abuseipdb.com/api/v2/check/"

	// PTuserName PassiveTotal account name
	PTuserName = os.Getenv("PTUSER")
	// PTAPIKey PassiveTotal API Key
	PTAPIKey             = os.Getenv("PTAPIKEY")
	hybridAnalysisKey    = os.Getenv("HAKEY")
	hybridAnalysisSecret = os.Getenv("HASECRET")
	vtAPIKey             = os.Getenv("VTAPIKEY")

	// flagIPAddress = os.Getenv("IPADDRESS")
	flagIPAddress = flag.String("ip", "", "IP Address to lookup")
	flagCLI       = flag.Bool("cli", false, "CLI Mode")
	flagLog       = flag.Bool("log", false, "Enable debug output")

	virusTotalBaseURL = "https://www.virustotal.com/api/v3/ip_addresses/"
	responseData      string
)

func queryPassiveTotal(endpoint string, Query string) string {
	if *flagLog {
		fmt.Println("Running RiskIQ queries")
	}
	httpClient := http.Client{}
	httpRequest, err := http.NewRequest("GET", endpoint+"?query="+Query, nil)
	httpRequest.SetBasicAuth(PTuserName, PTAPIKey)
	httpResponse, err := httpClient.Do(httpRequest)
	responseBytes := httpResponse.Body
	message, err := ioutil.ReadAll(responseBytes)
	prettyPrint, err := gabs.ParseJSON(message)
	if err != nil {
		log.Fatal("Risk IQ -Error ", err)
	}
	response := string(prettyPrint.String())
	// fmt.Println(response)
	return response
}

func queryAccountQuotas() {
	httpClient := http.Client{}
	httpRequest, err := http.NewRequest("GET", "https://api.passivetotal.org/v2/account/quota", nil)
	httpRequest.SetBasicAuth(PTuserName, PTAPIKey)
	httpResponse, err := httpClient.Do(httpRequest)
	responseBytes := httpResponse.Body
	message, err := ioutil.ReadAll(responseBytes)
	prettyPrint, err := gabs.ParseJSON(message)
	if err != nil {
		log.Fatal("RiskIQ - Error ", string(message), err)
	}
	fmt.Println(string(prettyPrint.String()))
}

func checkIPReputation(IPAddress string) string {
	if *flagLog {
		fmt.Println("Running AbuseIP DB queries")
	}

	httpClient := http.Client{}

	requestURL := abuseDBBaseURL + "?ipAddress=" + IPAddress
	httpRequest, _ := http.NewRequest("POST", requestURL, nil)
	httpRequest.Header.Add("Key", abuseDBKey)
	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	httpRequest.Header.Add("Accept", "application/json")

	httpResponse, err := httpClient.Do(httpRequest)
	if err != nil {
		log.Fatal(err)
	}
	httpResponseBytes, _ := ioutil.ReadAll(httpResponse.Body)
	if httpResponse.StatusCode == 401 {
		fmt.Println("AbuseIPDB - Error 401 - Check your API Key")

		return ""
	}
	// fmt.Println(string(httpResponseBytes))
	return (string(httpResponseBytes))

}

func queryHybridAnalysis(IPAddress string) string {
	if *flagLog {
		fmt.Println("Running Hybrid Analysis queries")
	}

	httpClient := http.Client{}
	requestURL := hybridAnalyisBaseURL
	requestBody := url.Values{}
	requestBody.Set("host", IPAddress)
	encodedRequest := []byte(requestBody.Encode())
	requestReader := bytes.NewReader(encodedRequest)
	httpRequest, err := http.NewRequest("POST", requestURL, requestReader)

	httpRequest.Header.Add("api-key", hybridAnalysisKey)
	// httpRequest.Header.Add("authority", "www.hybrid-analysis.com")
	httpRequest.Header.Add("user-agent", "Falcon Sandbox")
	httpRequest.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	httpResponse, err := httpClient.Do(httpRequest)
	responseBytes := httpResponse.Body
	message, err := ioutil.ReadAll(responseBytes)
	prettyPrint, err := gabs.ParseJSON(message)
	if err != nil {
		log.Fatal("Hybrid-Analysis Error ", string(message), err)
	}
	response := string(prettyPrint.String())
	// fmt.Println(response)
	return response
}

func queryVirusTotal(IPAddress string) string {
	if *flagLog {
		fmt.Println("Running VirusTotal queries")
	}

	httpClient := http.Client{}

	requestURL := virusTotalBaseURL + IPAddress
	httpRequest, err := http.NewRequest("GET", requestURL, nil)
	httpRequest.Header.Add("x-apikey", vtAPIKey)
	httpResponse, err := httpClient.Do(httpRequest)
	responseBytes := httpResponse.Body
	message, err := ioutil.ReadAll(responseBytes)
	prettyPrint, err := gabs.ParseJSON(message)
	if err != nil {
		log.Fatal("Virus Total Error ", err)
	}
	response := string(prettyPrint.String())
	// fmt.Println(response)
	return response
}

func main() {
	flag.Parse()
	if *flagCLI {

		handleRequest()
	} else {
		lambda.Start(handleRequest)
	}
}

func handleRequest() {
	var IPAddress string
	var cacheMiss error

	// CLI Mode

	// // parse build flag
	if !*flagCLI {
		IPAddress = os.Getenv("IPADDRESS")

		client := redis.NewClient(&redis.Options{
			Addr:     redisCluster + ":6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})

		// Check redis cluster status
		_, clientError := client.Ping().Result()
		if clientError != nil {
			if !*flagCLI {
				log.Fatal(clientError)
			}
		}
		responseData, cacheMiss = client.Get(IPAddress).Result()
		if responseData != "" {
			fmt.Println("cache hit!")
		}

	} else {
		IPAddress = *flagIPAddress
	}

	var redisData string
	if cacheMiss != nil || *flagCLI {

		// Adding missing record
		if cacheMiss != nil {
			log.Println("Record", IPAddress, "not found in cache, performing lookup")
			// Sample IP - 91.213.233.25 - CN - Malicious
			// Sample IP - 120.79.27.209 - CN - Malicious
		}
		// fmt.Println(IPAddress)

		// VirusTotal
		vtResponse, _ := gabs.ParseJSON([]byte(queryVirusTotal(IPAddress)))
		// AbuseIPDB Check
		abuseDBResponse, _ := gabs.ParseJSON([]byte(checkIPReputation(IPAddress)))
		// Passive Total
		passiveTotalResponse, _ := gabs.ParseJSON([]byte(queryPassiveTotal(enrichment, IPAddress)))
		// HybridAnalysis
		hybridAnalysisResponse, _ := gabs.ParseJSON([]byte(queryHybridAnalysis(IPAddress)))

		// update response object
		responseContainer := gabs.New()
		responseContainer.SetP(abuseDBResponse.Data(), "AbuseDB")
		responseContainer.SetP(passiveTotalResponse.Data(), "RiskIQ")
		responseContainer.SetP(vtResponse.Data(), "VirusTotal")
		responseContainer.SetP(hybridAnalysisResponse.Data(), "HybridAnalysis")
		redisData = responseContainer.String()
		if !*flagCLI && cacheMiss != nil {
			client := redis.NewClient(&redis.Options{
				Addr:     redisCluster + ":6379",
				Password: "", // no password set
				DB:       0,  // use default DB
			})
			_, err := client.SetNX(IPAddress, redisData, 336*time.Hour).Result()

			if err != nil {
				log.Fatal(err)
			}
		}
		responseData = redisData

		//
	}
	responseContainer, _ := gabs.ParseJSON([]byte(responseData))
	// Info
	fmt.Println("\nIP Address:", IPAddress)
	fmt.Println("AS:", responseContainer.Path("RiskIQ.autonomousSystemName").Data(), "-", responseContainer.Path("RiskIQ.autonomousSystemNumber").Data())
	fmt.Println("Domain:", responseContainer.Path("AbuseDB.data.domain").Data().(string))
	fmt.Println("Country:", responseContainer.Path("RiskIQ.country").Data())
	fmt.Println("Usage:", responseContainer.Path("AbuseDB.data.usageType").Data())

	var riskRating string

	vtScoreMal := responseContainer.Path("VirusTotal.data.attributes.last_analysis_stats.malicious").Data().(float64) * 10
	vtScoreSus := responseContainer.Path("VirusTotal.data.attributes.last_analysis_stats.suspicious").Data().(float64) * 10
	AIDBScore := responseContainer.Path("AbuseDB.data.abuseConfidenceScore").Data().(float64)
	combinedScore := vtScoreSus + vtScoreMal + AIDBScore
	if combinedScore < 60 {
		riskRating = "Low"
	}
	if combinedScore >= 60 {
		riskRating = "Medium"
	}
	if combinedScore >= 80 {
		riskRating = "High"
	}
	fmt.Println("\nRisk Rating:", riskRating, combinedScore)

	// Abuse
	fmt.Println("Compromised:", responseContainer.Path("RiskIQ.everCompromised"))
	fmt.Println("AbuseDB Confidence Score:", AIDBScore)
	fmt.Println("VirusTotal Malicious Score:", vtScoreMal)
	fmt.Println("VirusTotal Suspicious Score:", vtScoreSus)

}

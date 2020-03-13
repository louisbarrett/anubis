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
	"sync"
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

type anubisResponse struct {
	IPAddress   string
	ASName      interface{}
	ASNumber    interface{}
	Domain      string
	Country     interface{}
	Usage       interface{}
	Compromised interface{}
	vtScoreMal  float64
	vtScoreSus  float64
	AIDBScore   float64
	Total       float64
	RiskRating  string
}

var (
	redisCluster     = os.Getenv("REDIS_CLUSTER")
	recordExpiration = 336                        // Number of hours to store cached record
	abuseDBKey       = os.Getenv("ABUSEDBSECRET") //
	abuseDBBaseURL   = "https://www.abuseipdb.com/api/v2/check/"
	// PTuserName PassiveTotal account name
	PTuserName = os.Getenv("PTUSER")
	// PTAPIKey PassiveTotal API Key
	PTAPIKey             = os.Getenv("PTAPIKEY")
	hybridAnalysisKey    = os.Getenv("HAKEY")
	hybridAnalysisSecret = os.Getenv("HASECRET")
	vtAPIKey             = os.Getenv("VTAPIKEY")

	flagLambda    = flag.Bool("lambda", false, "Toggle lambda execution")
	flagIPAddress = flag.String("ip", "", "IP Address to lookup")
	flagCLI       = flag.Bool("cli", false, "CLI Mode")
	flagLog       = flag.Bool("log", false, "Enable debug output")
	flagDev       = flag.Bool("dev", false, "Internal development")
	flagJSON      = flag.Bool("json", false, "Output in JSON")

	virusTotalBaseURL = "https://www.virustotal.com/api/v3/ip_addresses/"

	runningJobs = new(sync.WaitGroup)

	responseData string
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

func checkAbuseDB(IPAddress string) string {
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

func anubisVerify(IPAddress string, checkCache bool, recordExpiration int, wg *sync.WaitGroup) {
	var cacheMiss error
	var redisData string
	defer wg.Done()
	// Check if caching is enabled
	if checkCache {
		// Create redis client
		client := redis.NewClient(&redis.Options{
			Addr:     redisCluster + ":6379",
			Password: "",
			DB:       0,
		})
		// Check redis cluster status
		_, clientError := client.Ping().Result()
		if clientError != nil {
			log.Fatal(clientError)
			wg.Done()
		}
		// Capture cache response
		responseData, cacheMiss = client.Get(IPAddress).Result()
		if responseData != "" {
			if *flagLog {
				log.Println("cache hit for", IPAddress)
			}
		}
	}
	// Perform API lookups
	if cacheMiss != nil || checkCache == false {
		// Log lookup
		if *flagLog {
			log.Println("Record", IPAddress, "not found in cache, performing lookup")
			// Sample IP - 120.79.27.209 - CN - Malicious
		}
		// VirusTotal
		vtResponse, _ := gabs.ParseJSON([]byte(queryVirusTotal(IPAddress)))
		// AbuseIPDB Check
		abuseDBResponse, _ := gabs.ParseJSON([]byte(checkAbuseDB(IPAddress)))
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
		if checkCache && cacheMiss != nil {
			client := redis.NewClient(&redis.Options{
				Addr:     redisCluster + ":6379",
				Password: "",
				DB:       0,
			})
			_, err := client.SetNX(IPAddress, redisData, 336*time.Hour).Result()

			if err != nil {
				log.Fatal("Error setting cache record", err)
			}
		}
		// Expose data from redis cluster
		responseData = redisData
	}

	// Parse response from cache or API lookups
	responseContainer, err := gabs.ParseJSON([]byte(responseData))
	if err != nil {
		log.Fatal(err)
	}

	abuseReport := anubisResponse{
		IPAddress:   IPAddress,
		ASName:      (responseContainer.Path("RiskIQ.autonomousSystemName").Data()),
		ASNumber:    responseContainer.Path("RiskIQ.autonomousSystemNumber").Data(),
		Domain:      responseContainer.Path("AbuseDB.data.domain").Data().(string),
		Country:     responseContainer.Path("RiskIQ.country").Data(),
		Usage:       responseContainer.Path("AbuseDB.data.usageType").Data(),
		vtScoreMal:  responseContainer.Path("VirusTotal.data.attributes.last_analysis_stats.malicious").Data().(float64) * 10,
		vtScoreSus:  responseContainer.Path("VirusTotal.data.attributes.last_analysis_stats.suspicious").Data().(float64) * 10,
		AIDBScore:   responseContainer.Path("AbuseDB.data.abuseConfidenceScore").Data().(float64),
		Compromised: responseContainer.Path("RiskIQ.everCompromised"),
	}

	// Create risk rating from scores
	combinedScore := abuseReport.vtScoreSus + abuseReport.vtScoreMal + abuseReport.AIDBScore
	abuseReport.Total = combinedScore
	if combinedScore < 60 {
		abuseReport.RiskRating = "Low"
	}
	if combinedScore >= 60 {
		abuseReport.RiskRating = "Medium"
	}
	if combinedScore >= 80 {
		abuseReport.RiskRating = "High"
	}

	// Send response to the appropriate channel
	// rawReport <- abuseReport
	// fmt.Println(abuseReport)
	if *flagJSON {
		reportJSON := gabs.Wrap(abuseReport)
		fmt.Println(reportJSON.String())

	} else {
		// make cute report
		fmt.Println("\n", "IP Address:", abuseReport.IPAddress, "\n",
			"AS Name:", abuseReport.ASName, "-", abuseReport.ASNumber, "\n",
			"Domain:", abuseReport.Domain, "\n",
			"Country:", abuseReport.Country, "\n",
			"Usage:", abuseReport.Usage, "\n",
			"Risk Rating:", abuseReport.RiskRating, "-", abuseReport.Total, "\n",
			"VirusTotal Malicious Score:", abuseReport.vtScoreMal, "\n",
			"AbuseDB Confidence Score:", abuseReport.AIDBScore, "\n",
			"Compromised:", abuseReport.Compromised,
		)
	}
	// Update the waitgroup status and return
}

func handleRequest() {
	IPAddress := os.Getenv("IPADDRESS")
	runningJobs.Add(1)
	go anubisVerify(IPAddress, false, recordExpiration, runningJobs)
	runningJobs.Wait()

}

func main() {
	flag.Parse()
	flag.Set("lambda", "false")
	// CLI Execution options
	if *flagCLI {
		IPAddress := *flagIPAddress
		runningJobs.Add(1)
		go anubisVerify(IPAddress, false, recordExpiration, runningJobs)
		runningJobs.Wait()
	}
	// Lambda execution options
	if os.Getenv("LAMBDA") == "TRUE" {
		lambda.Start(handleRequest)
	}
	// development flags
	if *flagDev {

		// Import Bulk list of IP addresses from File, S3, or Event

		BulkLookup := []string{}
		// Process list of IP addresses
		BulkLookup = append(BulkLookup, "120.79.27.209")
		BulkLookup = append(BulkLookup, "120.79.27.249")
		BulkLookup = append(BulkLookup, "12.79.27.209")

		// Run anubis verification on addresses
		runningJobs.Add(len(BulkLookup))
		for index := range BulkLookup {
			go anubisVerify(BulkLookup[index], false, 336, runningJobs)
		}
		runningJobs.Wait()
	}

}

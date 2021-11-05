/*
//  Function-as-a-Service code for DATA650 Watson Assistant API lookups
//  IBM Cloud 'Functions' namespace
//  
*/
var request = require('request-promise');

// These probably aren't what you think they are
const IPINFOTOKEN = "amF2YXNjcmlwdCBpcyB0aGUgZGV2aWw=";
const APIKEY      = "cHl0aG9uIGlzIHRoZSB3YXk=";

var data = {
  item: null,
  
  getipinfo: function() {
    return request({
      "method":"GET", 
      "uri": "https://ipinfo.io/"+encodeURIComponent(data.item)+"?token="+encodeURIComponent(IPINFOTOKEN),
      "json": true
    }).then(function(response) {
        return response;
    })
  },
  
  // Submit an IP address to virustotal and request report
  // process for essential elements of information to return to the app
  getvtip: function() {
    return request({
      "method":"GET", 
      "uri": "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey="+encodeURIComponent(APIKEY)+"&ip="+encodeURIComponent(data.item),
      "json": true
    }).then(function(response) {
            // For debug..
            //console.log(Object.keys(response));
            var output = {};
            
            output.asn             = response.asn;
            output.country         = response.country;
            output.num_resolutions = response.resolutions.length;
            output.detected_urls   = response.detected_urls.length;
            output.undetected_urls = response.undetected_urls.length;
            
            var names  = [];
            output.resolutions = "";
            // If there are less than X domains, return in comma separated list. otherwise, just the count
            if (output.resolutions<100){
                response.resolutions.forEach(
                    function(v){names.push(v.hostname)}
                );
                output.resolutions = names.join(", ");
            }
            
            output.last_domain      = "";
            output.last_date        = "";
            // The list of resolutions is a list of objects of type date/domain, unordered.
            // This clause will find the most recent date and set the above blank variables
            if (output.num_resolutions>0) {
                var maxDate    = '0';
                var maxDateIdx = 0;
                for (var i=0; i<response.resolutions.length; i++){
                	var x      = response.resolutions[i];
                    var date   = x.last_resolved;
                    var domain = x.hostname;
                    if (date > maxDate){
                  	    maxDate    = date;
                        maxDateIdx = i;
                    }
                }
                output.last_domain = response.resolutions[maxDateIdx].hostname;
                output.last_date   = response.resolutions[maxDateIdx].last_resolved;
            }
            
            return output;
    })
  },
  
    // Submit a web domain to virustotal for report
    // process results into expected flattened json structure for follow-on app processing
    get_vt_domain: function() {
    return request({
      "method":"GET", 
      "uri": "https://www.virustotal.com/vtapi/v2/domain/report?apikey="+encodeURIComponent(APIKEY)+"&domain="+encodeURIComponent(data.item),
      "json": true,
    }).then(function(response) {
            // For debug..
            //console.log(Object.keys(response));
            
            var output = {};
            
            // Number of IP resolutions observed
            output.num_resolutions              = "resolutions" in response ? response.resolutions.length : 0;
            
            output.last_ip                      = "";
            output.last_date                    = "";
            // The list of resolutions is a list of objects of type date/ip, unordered.
            // This clause will find the most recent date and set the above blank variables
            if (output.num_resolutions>0) {
                var maxDate    = '0';
                var maxDateIdx = 0;
                for (var i=0; i<response.resolutions.length; i++){
                	var x    = response.resolutions[i];
                    var date = x.last_resolved;
                    var ip   = x.ip_address;
                    if (date > maxDate){
                  	    maxDate    = date;
                        maxDateIdx = i;
                  }
                }
                output.last_ip   = response.resolutions[maxDateIdx].ip_address;
                output.last_date = response.resolutions[maxDateIdx].last_resolved;
            }
            
            output.webutation_verdict = "";
            output.webutation_adult   = "";
            output.webutation_safety  = "";
            // If webutation scores are available, set them
            if ("Webutation domain info" in response) {
                var wdi = response["Webutation domain info"];
                output.webutation_adult    = "Adult content" in wdi ? wdi["Adult content"] : "";
                output.webutation_safety   = "Safety score"  in wdi ? wdi["Safety score"] : "";
                output.webutation_verdict  = "Verdict"       in wdi ? wdi["Verdict"] : "";
            }
            // Set the following if available
            output.domain_siblings                = "domain_siblings" in response ? response.domain_siblings.length: 0;
            output.detected_communicating_samples = "detected_communicating_samples" in response ? response.detected_communicating_samples.length : 0;
            output.detected_downloaded_samples    = "detected_downloaded_samples" in response ? response.detected_downloaded_samples.length : 0;
            output.firstSeen                      = "current_dns" in response ? response.current_dns.a.first_seen : "";
            output.whois                          = "whois" in response ? response.whois : "";
            return output;
    })
  }
}

// This gets called by the server when the API is called
function main(params) {
    var results = {  "params"        : params,
                     "virustotal"    : null,
                     "ipinfo"        : null  
                  };
    
    var promises = [];
    if (('ipv4' in params) || ('ipv6' in params)){
        if ('ipv4' in params){
            data.item = params.ipv4;
        }
        else {
            data.item = params.ipv6;
        }
        promises.push( 
            data.getipinfo().then(function(resp){ 
                results.ipinfo = resp;
            }));
        promises.push(
            data.getvtip().then(function(resp){
                    results.virustotal = resp; 
            }));
    }
    else if ('webdomain' in params){
        var a = params.webdomain;
        if ( a[a.length-1]=='/' ){
            a = a.substr(0, a.length-1);
        }
        data.item = a;
        promises.push(
            data.get_vt_domain().then(function(resp){
                    results.virustotal = resp; 
            }));
    }
    return Promise.all(promises).then((values) => {
        return results;
    });
}

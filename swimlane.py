import requests
import json
import base64
import sys

def url_search(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36', 'x-apikey': '4e801b187604ded940843c16909c8d5a2c598e57001d925296f48c79cb0c9317'}
    req_endpoint = 'https://www.virustotal.com/api/v3/urls/' + url_id
    response = requests.get(req_endpoint, headers=headers)
    return response

def url_analyse(url):
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.76 Safari/537.36', 'x-apikey': '4e801b187604ded940843c16909c8d5a2c598e57001d925296f48c79cb0c9317'}
    req_endpoint = 'https://www.virustotal.com/api/v3/urls'
    print(req_endpoint)
    response = requests.post(req_endpoint, headers=headers, data={'url': url})
    return response

def build_url_list(response):
    stuff = json.loads(response.text)
    thing = stuff['data']['attributes']['outgoing_links']
    thing.append(stuff['data']['attributes']['url'])
    return thing


def main(argv):
    print("start")
    input_url = argv[1]
    print(input_url)
    #query supplied url
    if(url_search(input_url).status_code != 200):
       # if the response returns anything other than 200 assume the analysis still needs to be run
       url_analyse(input_url)
    #now query the endpoint for the url report
    response=url_search(input_url)
    #create the list of related urls to query
    url_list = build_url_list(response)
    print(url_list)
    #output each result
    for url in url_list:
        if (url_search(url).status_code != 200):
            # if the response returns anything other than 200 assume the analysis still needs to be run
            url_analyse(url)
        print(url_search(url).text)


if __name__ == '__main__':
    main(sys.argv[0:])

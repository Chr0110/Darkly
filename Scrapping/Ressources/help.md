
# Scrapping 

Web scraping involves extracting data from websites using automated scripts or tools. While scraping is often used for legitimate purposes (e.g., data aggregation), it can also be exploited to extract sensitive data or overload servers.



## Exploitation

Example 1: Unprotected User Data
A website lists user information in paginated tables.
The table contains hidden fields with sensitive data (e.g., user IDs, emails).
A scraper extracts all pages of the table, including the hidden fields.
Example 2: No Rate Limiting
An API endpoint allows unlimited requests for product details.
A scraper continuously sends requests to gather the entire product catalog.
The data is used by competitors or leads to server resource exhaustion.
Example 3: Bypassing Anti-Scraping Measures
A website requires a CAPTCHA for accessing pages.
An attacker uses a headless browser (e.g., Puppeteer or Playwright) and a CAPTCHA-solving service to bypass the protection.
The attacker extracts the data at scale.


## Explanation 

robots.txt is a text file placed on a website's root directory that provides instructions to web robots (also known as web crawlers or spiders) about which parts of the website should or should not be crawled and indexed by search engines. It is used as part of the robots exclusion protocol (REP), a standard used by websites to communicate with web crawlers.

The file is typically used to manage and control the behavior of web crawlers, improving both the performance of a website and its SEO (Search Engine Optimization) strategy.


At http://localhost/robots.txt you get 

```
User-agent: *
Disallow: /whatever
Disallow: /.hidden
```

This tells all bots (User-agent: *) not to crawl or index pages under the /private/ directory.


The URL http://localhost/.hidden/ represents a directory path on a locally hosted web server that could potentially store sensitive or hidden files.


```
 Index of /.hidden/
../
amcbevgondgcrloowluziypjdh/                        29-Jun-2021 18:15                   -
bnqupesbgvhbcwqhcuynjolwkm/                        29-Jun-2021 18:15                   -
ceicqljdddshxvnvdqzzjgddht/                        29-Jun-2021 18:15                   -
doxelitrqvhegnhlhrkdgfizgj/                        29-Jun-2021 18:15                   -
eipmnwhetmpbhiuesykfhxmyhr/                        29-Jun-2021 18:15                   -
ffpbexkomzbigheuwhbhbfzzrg/                        29-Jun-2021 18:15                   -
ghouhyooppsmaizbmjhtncsvfz/                        29-Jun-2021 18:15                   -
hwlayeghtcotqdigxuigvjufqn/                        29-Jun-2021 18:15                   -
isufpcgmngmrotmrjfjonpmkxu/                        29-Jun-2021 18:15                   -
jfiombdhvlwxrkmawgoruhbarp/                        29-Jun-2021 18:15                   -
kpibbgxjqnvrrcpczovjbvijmz/                        29-Jun-2021 18:15                   -
ldtafmsxvvydthtgflzhadiozs/                        29-Jun-2021 18:15                   -
mrucagbgcenowkjrlmmugvztuh/                        29-Jun-2021 18:15                   -
ntyrhxjbtndcpjevzurlekwsxt/                        29-Jun-2021 18:15                   -
oasstobmotwnezhscjjopenjxy/                        29-Jun-2021 18:15                   -
ppjxigqiakcrmqfhotnncfqnqg/                        29-Jun-2021 18:15                   -
qcwtnvtdfslnkvqvzhjsmsghfw/                        29-Jun-2021 18:15                   -
rlnoyduccpqxkvcfiqpdikfpvx/                        29-Jun-2021 18:15                   -
sdnfntbyirzllbpctnnoruyjjc/                        29-Jun-2021 18:15                   -
trwjgrgmfnzarxiiwvwalyvanm/                        29-Jun-2021 18:15                   -
urhkbrmupxbgdnntopklxskvom/                        29-Jun-2021 18:15                   -
viphietzoechsxwqacvpsodhaq/                        29-Jun-2021 18:15                   -
whtccjokayshttvxycsvykxcfm/                        29-Jun-2021 18:15                   -
xuwrcwjjrmndczfcrmwmhvkjnh/                        29-Jun-2021 18:15                   -
yjxemfsgdlkbvvtjiylhdoaqkn/                        29-Jun-2021 18:15                   -
zzfzjvjsupgzinctxeqtzzdzll/                        29-Jun-2021 18:15                   -
README                                             29-Jun-2021 18:15                  34
```


by the end of each folder succession you find a file README so I used a scrapping script to collect approximately 36,557 scraped README files.

I opened the files while scrapping and appended the content on a single file to get  by the end the FLAG

```
--- Content from http://localhost/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/juavephzegfusfrqelvumphzat/ ---
Demande à ton voisin du dessus  


--- Content from http://localhost/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/kbjjgbfcbchslgysntmtmcxzyr/ ---
Non ce n'est toujours pas bon ...


--- Content from http://localhost/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/lmpanswobhwcozdqixbowvbrhw/ ---
Hey, here is your flag : d5eec3ec36cf80dce44a896f961c1831a05526ec215693c8f2c39543497d4466


--- Content from http://localhost/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/mfmtemmsbpftlvuuuwitbydbbt/ ---
Toujours pas tu vas craquer non ?


--- Content from http://localhost/.hidden/whtccjokayshttvxycsvykxcfm/igeemtxnvexvxezqwntmzjltkt/nzzuqitxumdibwksdfdbczvahq/ ---
Tu veux de l'aide ? Moi aussi !  

```

## Prevention and Mitigation Strategies
Here’s how to secure a website or API against scraping:

Require user authentication to access sensitive data.
Use role-based access control to ensure only authorized users can view specific content.
Implement rate limits to restrict the number of requests a user or IP can make in a given time.
Example: Use a WAF (Web Application Firewall) to detect and block excessive requests.
Avoid exposing sensitive data in the HTML or client-side JavaScript.
Implement bot detection mechanisms, such as:
CAPTCHAs
Behavioral analysis (e.g., mouse movements, keystroke patterns)
IP blacklisting for known malicious sources.

# Information Gathering
> Mục tiêu: dyson.com
> 
> Thực hiện: Trần Tiến Đức
> 
> Cập nhật lần cuối: 02/07/2025

# Mục lục
- [Information Gathering](#information-gathering)
- [Gathering Information Using Whois Lookup](#gathering-information-using-whois-lookup)
- [Discovering Websites On The Same Server](#discovering-websites-on-the-same-server)
- [Discovering Subdomains](#discovering-subdomains)
- [Discovering Sensitive Files](#discovering-sensitive-files)
- [Google Hacking](#google-hacking)

# Scope Based Recon
Phương pháp `Scope Based Recon` chia quy trình recon dựa trên phạm vi, giúp tiết kiệm thời gian, biết chính xác những gì cần tìm kiếm, dễ dàng tự động hóa quy trình.

Dựa vào phương pháp này, ta sẽ chia thành 3 phạm vi:
- Small Based Recon
- Medium Based Recon
- Large Based Recon

Ta sẽ đi vào lần lượt từng scope đối với mục tiêu là `dyson.com`

# Small Based Recon
## Technology Fingerprinting
`Technology Fingerprinting` là kỹ thuật xác định công nghệ mà một website hoặc ứng dụng web đang sử dụng, như: CMS, framework, server, ngôn ngữ lập trình, thư viện JS, font,...

Ở đây ta sẽ sử dụng **`Wappalyzer`**

<img width="597" height="962" alt="image" src="https://github.com/user-attachments/assets/69d723c5-a096-481f-a6f1-854fe948ba9e" />

Thu về được khá nhiều thông tin về công nghệ mà `dyson` đang sử dụng, có thể tóm tắt nó như sau:

|Technology Category			|Detected Technology
|---------------------------------------|------------------------
| Ecommerce | Cart Functionality, Amazon Webstore
| CMS | Adobe Experience Manager
| Webmail | Microsoft 365, Apple iCloud Mail
| Programming languages | Java, PHP
| UI Frameworks | Bootstrap
| Web servers | Apache HTTP Server, Microsoft HTTPAPI (2.0)
| Payment proccessors | Affirm (2), Afterpay (1.32.11)
| PaaS | Amazon Web Services
| JavaScript Frameworks | Handlebars
| Security | HSTS, Akamai Bot Manager, Riskified
| SSL/TLS certificate authorities | DigiCert
| RUM | New Relic, Akamai mPulse, Boomerang
| Performance | Queue-it (2.0.52), Priority Hints, Lozad.js
| JavaScript libraries | jQuery (3.6.0), core-js (2.6.12), Lozad.js, Boomerang, Slick (1.9.0)
| Cookie compliance | OneTrust
| CDN | Akamai, jsDelivr, Amazon S3, Cloudflare, cdnjs, jQuery CDN
| ... | ...

## Directory Enumeration
`Directory Enumeration` là kỹ thuật dùng để tìm ra các directory hoặc file ẩn trên website hoặc máy chủ

Có khá nhiều tool giúp chúng ta chuyện này nhưng trong bài này ta sẽ chỉ tập trung vào sử dụng là **`ffuf`** và **`dirsearch`**

Dựa vào thông tin về công nghệ mà `dyson` sử dụng mà ta đã thu thập ở trước, ta biết được rằng website sử dụng `Akamai` đây là hệ thống phát hiện chặn bot. Nếu sử dụng **`ffuf`** cũng như **`dirsearch`** mà không giả lập giống như một browser kỹ càng thì rất dễ bị `403 Forbidden`

Để làm được như vậy, ta cần cũng cấp cho nó những header giống với browser khi gửi request. Đầu tiên bắt request bằng **`burp suite`**, sau đó lấy header bỏ vào tool chạy

<img width="1502" height="825" alt="image" src="https://github.com/user-attachments/assets/45f5b4e4-0e31-477f-9739-8a5e9e52661e" />

Đối với **`ffuf`**, ta dùng `-H` để đính kèm header khi chạy, dùng thêm `-rate` để giới hạn tốc độ gửi, tránh bị chặn khi gửi quá nhiều req/s
<img width="1580" height="463" alt="image" src="https://github.com/user-attachments/assets/d46181a9-fd68-4546-8dae-7cebec1739aa" />
<img width="727" height="706" alt="image" src="https://github.com/user-attachments/assets/ccddc182-1031-4b57-a414-ae65e662b30e" />
<img width="903" height="461" alt="image" src="https://github.com/user-attachments/assets/6a61ccbc-c0c8-474d-9b70-ff0c24de73ef" />

Đối với **`dirsearch`** có option `--headers-file` sẽ tiện hơn trong việc thay đổi header, cũng như gặp các status code 30x cũng sẽ hiện rõ là sẽ redirect tới đâu, khá là tiện

<img width="793" height="733" alt="image" src="https://github.com/user-attachments/assets/90ec314c-78df-469a-969c-3dbe45512d63" />
<img width="1440" height="746" alt="image" src="https://github.com/user-attachments/assets/42dcc56e-4f63-45e3-9adc-ff666f6f6a29" />


## Port Scanning
`Port Scanning` là kỹ thuật để phát hiện port nào đang mở ở trên website hoặc máy chủ

Ở đây ta sẽ dùng **`rustscan`** mang lại hiệu suất nhanh hơn **`nmap`**
```bash
┌──(trntd㉿kali)-[~/Documents/tools/dirsearch]
└─$ rustscan -a dyson.com                         
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: allowing you to send UDP packets into the void 1200x faster than NMAP

[~] The config file is expected to be at "/home/trntd/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 52.59.122.122:80
Open 52.59.122.122:443
[~] Starting Script(s)
[~] Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-02 05:54 EDT
Initiating Ping Scan at 05:54
Scanning 52.59.122.122 [4 ports]
Completed Ping Scan at 05:54, 0.02s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 05:54
Completed Parallel DNS resolution of 1 host. at 05:54, 0.04s elapsed
DNS resolution of 1 IPs took 0.04s. Mode: Async [#: 2, OK: 1, NX: 0, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 05:54
Scanning ec2-52-59-122-122.eu-central-1.compute.amazonaws.com (52.59.122.122) [2 ports]
Discovered open port 443/tcp on 52.59.122.122
Discovered open port 80/tcp on 52.59.122.122
Completed SYN Stealth Scan at 05:54, 0.23s elapsed (2 total ports)
Nmap scan report for ec2-52-59-122-122.eu-central-1.compute.amazonaws.com (52.59.122.122)
Host is up, received reset ttl 255 (0.050s latency).
Scanned at 2025-08-02 05:54:19 EDT for 0s

PORT    STATE SERVICE REASON
80/tcp  open  http    syn-ack ttl 64
443/tcp open  https   syn-ack ttl 64

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds
           Raw packets sent: 6 (240B) | Rcvd: 4 (172B)
```
Nó chỉ mở 2 port cho `HTTP` và `HTTPS`, cũng không bất ngờ lắm, nó mà mở port khác như 22 là tới công chuyện liền 🤣

## JS Recon
...


## Google Dorking & GitHub Dorking
`Google Dorking` và `GitHub Dorking` đều là kỹ thuật truy vấn nâng cao giúp tìm kiếm thông tin nhạy cảm hoặc hữu ích từ các nguồn công khai (Google hoặc GitHub)

Về `Goole Dorking`, ta có thể sử dụng **`Fast-Google-Dorks-Scan`**
<img width="755" height="845" alt="image" src="https://github.com/user-attachments/assets/b8c0164d-db03-4e05-9027-f531b2a8fe82" />
<img width="755" height="842" alt="image" src="https://github.com/user-attachments/assets/e90223b9-4375-4e68-8f2c-afeab53ddeb9" />

Còn về `GitHub Dorking` ta có thể sử dụng **`GitDorker`**

`python GitDorker.py -tf github_API.txt -q dyson.com -d Dorks/medium_dorks.txt -o dyson`
<img width="1290" height="475" alt="image" src="https://github.com/user-attachments/assets/361c8594-8cfa-497d-841f-0e105f81baf5" />
Sau khi chạy xong nó sẽ lưu kết quả vào file CSV
<img width="1353" height="731" alt="image" src="https://github.com/user-attachments/assets/0d2bb83a-2086-4868-ad9b-018bda41edd1" />
<img width="1354" height="134" alt="image" src="https://github.com/user-attachments/assets/08f995db-34cf-472a-b8c4-6a8b0fcf9c43" />

# Medium Based Recon
## Subdomain Enumeration
Ở đây ta sẽ sử dụng 2 tool là **`assetfinder`** và **`subfinder`**

`assetfinder --subs-only dyson.com > sub_assetfinder.txt`

`subfinder -d dyson.com -v > sub_finder.txt`

Dùng **`wc`** thì biết được rằng **`assetfinder`** cho về nhiều kết quả hơn
<img width="536" height="167" alt="image" src="https://github.com/user-attachments/assets/d3d8c033-363e-4b20-b5e1-4e853d1fad9d" />
<img width="513" height="802" alt="image" src="https://github.com/user-attachments/assets/dfb5baba-1019-4ee7-b588-a3d4a06f5093" />

Tiếp theo ta sẽ dùng **`httpx`** để xác định xem subdomain nào đang hoạt động dựa trên status code
`cat sub_assetfinder.txt | httpx -fc 404 -title -wc -sc -ct -cl -web-server -asn -location > sub2_assetfinder.txt`

Có hơn 600 kết quả trả về
<img width="1304" height="563" alt="image" src="https://github.com/user-attachments/assets/f3b95229-4a24-4f99-b8b9-debf3bc54ddb" />
<img width="1248" height="290" alt="image" src="https://github.com/user-attachments/assets/bd701301-61c3-47ef-aef8-65d2874c154b" />


## Template Based Scanning
**`Template Based Scanning`** là kỹ thuật dùng để kiểm tra các lỗ hổng bảo mật, cấu hình sai,... bằng cách sử dụng các file tempalte định nghĩa sẵn. Ở đây ta sẽ sử dụng **`nuclei`**
```bash
┌──(trntd㉿kali)-[~/nuclei-templates/code]
└─$ nuclei -target https://www.dyson.com

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   v3.4.7

                projectdiscovery.io

[INF] Current nuclei version: v3.4.7 (latest)
[INF] Current nuclei-templates version: v10.2.6 (latest)
[WRN] Scan results upload to cloud is disabled.
[INF] New templates added in latest release: 41
[INF] Templates loaded for current scan: 8237
[INF] Executing 8036 signed templates from projectdiscovery/nuclei-templates
[WRN] Loading 201 unsigned templates for scan. Use with caution.
[INF] Targets loaded for current scan: 1
[INF] Templates clustered: 1770 (Reduced 1664 Requests)
[INF] Using Interactsh Server: oast.fun
[waf-detect:akamai] [http] [info] https://www.dyson.com
[tls-version] [ssl] [info] www.dyson.com:443 ["tls12"]
[tls-version] [ssl] [info] www.dyson.com:443 ["tls13"]
[http-missing-security-headers:permissions-policy] [http] [info] https://www.dyson.com
[http-missing-security-headers:x-frame-options] [http] [info] https://www.dyson.com
[http-missing-security-headers:x-content-type-options] [http] [info] https://www.dyson.com
[http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] https://www.dyson.com
[http-missing-security-headers:referrer-policy] [http] [info] https://www.dyson.com
[http-missing-security-headers:clear-site-data] [http] [info] https://www.dyson.com
[http-missing-security-headers:cross-origin-embedder-policy] [http] [info] https://www.dyson.com
[http-missing-security-headers:cross-origin-opener-policy] [http] [info] https://www.dyson.com
[http-missing-security-headers:cross-origin-resource-policy] [http] [info] https://www.dyson.com
[http-missing-security-headers:strict-transport-security] [http] [info] https://www.dyson.com
[http-missing-security-headers:content-security-policy] [http] [info] https://www.dyson.com
[tech-detect:akamai] [http] [info] https://www.dyson.com
[caa-fingerprint] [dns] [info] www.dyson.com
[dns-saas-service-detection:akamai-cdn] [dns] [info] www.dyson.com ["dyson.com.edgekey.net"]
[ssl-issuer] [ssl] [info] www.dyson.com:443 ["DigiCert Inc"]
[ssl-dns-names] [ssl] [info] www.dyson.com:443 ["www.dysonindie.com","www.mimosatrust.com","stylingtour.dyson.at","www.dysonmalmesbury.co.uk","www.sa.dyson.com","forbusiness.dyson.com.sg","shop.dyson.cn","shop.dyson.co.th","shop.dyson.de","test-shop.dyson.com.au","www.dyson.cn","www.dyson.es","www.dyson.nl","www.dyson.com","oldmedia.dyson.com","reviews.dyson.com","www.dyson.dk","beta.dyson.com.au","shop.dyson.no","shop.dyson.tw","stage.dyson.com.au","www.dyson.ch","www.dyson.co.nz","www.dyson.my","service.dyson.com","support.dyson.pl","www.jamesanddeirdredysontrust.com","acpsirextsit.dyson.hk","pdev.dyson.hk","support.dyson.com.sg","www.dysonrecall.com","www.starandstormfoundation.com","acpsirextdev.dyson.hk","shop.dyson.at","shop.dyson.dk","shop.dyson.es","shop.dyson.hk","shop.dyson.pl","staging.dyson.co.nz","staging.shop.dyson.co.th","troubleshooting.dyson.com","www.dyson.ae","shop.fi.dyson.com","www.dyson.be","www.dyson.com.ee","www.dyson.com.sg","www.dyson.hk","www.dyson.lt","www.dyson.se","www.dysonbrandcentre.com","psit.dyson.hk","shop.dyson.ae","shop.dyson.my","staging.shop.dyson.my","tandcs.dyson.com","www.dyson.at","www.dyson.co.il","www.fi.dyson.com","forbusiness.dyson.pl","m2admin.dyson.com.au","media.dyson.com","shop.dyson.com.sg","shop.dyson.nl","www.dyson.com.au","www.dyson.com.kh","p.dyson.hk","shop.dyson.be","shop.dyson.co.il","support.dyson.com.au","upgrade.dyson.cn","www.dyson.co.jp","www.dyson.de","www.dyson.it","feedback.dyson.com","rework.dysonrecall.com","shop.dyson.co.nz","support.dyson.co.th","support.dyson.hk","www.bluesurftrust.com","www.careers.dyson.com","www.dyson.fr","admin.dyson.com.au","shop.dyson.ch","shop.dyson.com.au","shop.dyson.it","shop.dyson.se","stage.m2admin.dyson.com.au","www.dyson.co.th","www.dyson.ee","acpsirext.dyson.hk","shop.dyson.fr","www.dyson.ma","www.dysoncanada.ca"]                                          
[INF] Scan completed in 2m. 19 matches found.
```
Có thể thấy `dyson` thiếu nhiều cơ chế bảo mật cơ bản như `content-security-policy`, `strict-transport-security`, `x-content-type-options`, `referrer-policy`,...

# Large Scope Recon
## Gathering Information Using Whois Lookup

Ở đây ta sẽ sử dụng công cụ **`whois`** ở **who.is**
<img width="826" height="206" alt="image" src="https://github.com/user-attachments/assets/dd715e9d-ead0-4fa6-ae31-ea2fb953fd8b" />
<img width="824" height="204" alt="image" src="https://github.com/user-attachments/assets/4c5ad6dc-aff4-48c7-8679-202c68f4a425" />
<img width="821" height="209" alt="image" src="https://github.com/user-attachments/assets/a0faff94-bef3-49ee-934a-4db7be938ff0" />
<img width="734" height="889" alt="image" src="https://github.com/user-attachments/assets/194e5e57-7787-468f-953c-a8f5f71d3861" />


Ta sẽ thu thập được những thông tin cơ bản sau:
|Mục                    |Thông tin
|-----------------------|---------------------------
|Địa chỉ IP             |52.59.125.242
|Nhà đăng ký            |CSC Corporate Domains, Inc
|WHOIS Server           |whois.corporatedomains.com
|Ngày đăng ký           |29/10/1997
|Ngày cập nhật          |10/24/2024
|Ngày hết hạn           |10/28/2025
|Điện thoại             |+44.1666827200
|Fax                    |+44.1666828040
|Email                  |domainnames [at] dyson [dot] com


Thông tin liên hệ:
|Vai trò        |Tên liên hệ            |Tổ chức        |Quốc gia
|---------------|-----------------------|---------------|-------------
|Registrant     |Domain Administrator   |Dyson Ltd      |Wiltshire, GB
|Admin          |Domain Administrator   |Dyson Ltd      |Wiltshire, GB
|Tech           |Domain Administrator   |Dyson Ltd      |Wiltshire, GB



## Discovering Websites On The Same Server
Để tim được những website khác có cùng server (địa chỉ IP) ta sử dụng `Reverse IP lookup`.
`Reverse IP lookup` là quá trình dùng địa chỉ IP để tìm ra các tên miền (domain) được host trên cùng địa chỉ IP đó.

Ở viewdns.info có hỗ trợ chức năng Reverse IP lookup [tại đây](https://viewdns.info/reverseip/). Đây là danh sách Websites On The Same Server
|Websites               |
|-----------------------|
bluesurftrust.com	
buydysonairblade.uk	
dyson.bg	
dyson.cn	
dyson.co.jp	
dyson.co.kr	
dyson.co.th	
dyson.com	
dyson.com.ar	
dyson.com.cy	
dyson.com.jm	
dyson.com.kh	
dyson.com.pa	
dyson.com.ru	
dyson.cr	
dyson.do	
dyson.gt	
dyson.is	
dyson.lu	
dyson.ro	
dyson.si	
dysonbrandcentre.com	
dysoninstitute.co.uk	
dysonmalmesbury.co.uk	
dysonoffice.com	
dysonoutlet.co.uk	
...

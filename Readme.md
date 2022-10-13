# CDS ( Inbrowser Cryptojacking or Cryptomining Detection System )

CDS detects inbrower cryptojacking or cryptomining caused by malicious javascript libraries 
which uses our CPU's processing power to mine cryptocurrencies.


## Project Description:
In recent years cryptocurrency has become one of the most important forms of currency, having very high market value. It has been integrated in business and finance and is now used everywhere. People who wish to take part in the crypto community and earn currency (coins) must put some effort (computational power) and solve certain problems/puzzles. This is where attackers try to take advantage of vulnerabilities and weaknesses such that they are able to use another person’s computational power without their knowledge, and get rewards (coins) for themselves. This is called Cryptojacking. For now, as a prerequisite to making a system that would detect Cryptojacking, the first step is to be able to detect Cryptomining itself. This is what this project is about and we hope to evolve it further in the future.

## Analysis:
Our analysis is a hybrid of two analysis methods, and it uses both these methods to find hints that would imply that the system is currently mining cryptocurrencies. This involves the following:
Static Analysis:
In static analysis, we do not focus on the results given by running the target (mining script in this case) but instead try to get by analyzing the file in itself. For this we have first collected a list of names of various mining scripts. We got this list from the “Crypto Jacking Alexa Top 1million websites'' dataset. This dataset contains various useful things such as:
A list of URLs that had mining scripts
HTML files of sites hosting mining scripts
The JavaScript script files that were being used in said websites
The third point is what we’re going to focus on. This list contains a lot of different files, each which were used as mining scripts in various websites. So for static analysis, our main approach was to firstly get all the JavaScript files being used in a website. We would then compare each of these files with the list of mining scripts and see if we find a match. If a match is found then it is highly likely that the website we ran is doing some sort of mining.



```
l1 = os.listdir("C:/Users/windows/Desktop/ProcessExplorer/scripts")
for script in script_files:
    for l in l1:
        if(script.find(l)!=-1):
                mallist.append(script)
                malfile=True
```
Comparing crypto jacking script with the scraped script form the malicious website.


## Dynamic Analysis:
In dynamic analysis we focus on the results we would get after we have run the mining script. This means we will first run the mining script and then see how it impacts the system. Based on that we can make some rules that would help us classify whether or not a system is currently mining or not. In this we took two three things into account. Firstly we look at CPU usage. This is one of the most visible indicators that we can use. Since mining requires a lot of computational power and is computationally intensive, mining would lead to sufficient CPU usage. So keeping abnormally high CPU usage in check is very important. The second thing to take into account is, is this abnormally high CPU usage based on a single process? Or is it just because of the system’s overall state. If there is abnormally high CPU usage because of just one process, then it also raises suspicions, especially if that process is using abnormally high CPU power. Thirdly in this project's perspective, since we are mostly focusing on Web Browsers and mining/cryptojacking on the web, we will check if the process using a lot of CPU resources is a web browser process or not. If it is, then that would mean that there is a good chance that mining is being done.

For this project, we are writing code in Python. For the first part, where we calculate the CPU usage, we use the psutil module. This module gives us information about and relevant to the running processes, CPU, memory, disk etc. From this module, we call the cpu_percent() function. It tells us the usage of the CPU as a percentage. We can use this and threshold it to above 90% usage. So if the CPU usage crosses 85%, this is a hint of potential mining.

The second thing we’re checking is that, is there one single process that is taking a lot of CPU power? We do this using ProcessExplorer. It is similar to Process Hacker and it shows the CPU usage per process. We get logs from this tool after every 1 second. We have automated this process by using the pywinauto module. The log file is then read into a pandas dataframe. All irrelevant rows (Suspended processes or processes using VERY less CPU power) are removed, and the dataframe is sorted to give us the process which has the highest CPU usage. If this CPU usage is > 85, we can consider this as suspicious in the sense that there might be mining.

Lastly, we check if the process with the highest CPU usage is a browser process or not. If it is then we can be suspicious that mining may be happening.

So in total, if the CPU usage crosses 85%, a single process has CPU usage > 85%, the JavaScript files in the website match with the predefined list of miner scripts and the process with CPU usage > 85% is a browser process. Then we say, that mining is being done.
```
    if((sorted_on_cpu_usage.loc[0]['Process']=="msedge.exe")or(sorted_on_cpu_usage.loc[0]['Process']=="firefox.exe")):
        browserbool=True
 
    if(float(sorted_on_cpu_usage.loc[0]['CPU']) > 85):
        cpubool=True
 
   
    if((browserbool==True) and (cpubool==True) and (malfile==True) and (avgcpualert==True)):
        print("The process "+str(sorted_on_cpu_usage.loc[0]['Process'])+" with PID "+ str(sorted_on_cpu_usage.loc[0]['PID']) +" is CryptoMining")
```

from pywinauto import application
import os
import pandas as pd
from time import sleep
import psutil
import requests
from bs4 import BeautifulSoup

script_files = []

r  = requests.get("https://www.coinimp.com/dashboard")
data = r.text
soup = BeautifulSoup(data,'html.parser')


sources=soup.findAll('script',{"src":True})
for source in sources:
    # print(source['src'])
    script_files.append(source['src'])


# print(script_files)

        
                
# print(mallist," ",malfile)


# req = requests.get("https://www.coinimp.com/dashboard", timeout = 5)

# page = BeautifulSoup(req.content, "html.parser")
# page_text = page.get_text()
# print(page.prettify())




# fan_speed = psutil.sensors_fans()

# temps = psutil.sensors_temperatures()



# print(temps['coretemp'][1][0], temps['coretemp'][1][1])
# print(temps['coretemp'][2][0], temps['coretemp'][2][1])

# print(temps['coretemp'][1][1])

# print(temps)


app = application.Application()
app.start("E:/ProcessExplorer/procexp64.exe")

print(app.windows()[0])

proc_exp = app['Process Explorer - Sysinternals: www.sysinternals.com [DESKTOP-M4VKIUP\HP]']

l1 = os.listdir("E:/ProcessExplorer/scripts")


i = 0
while True:

    mallist=[]
    malfile=False

    for script in script_files:
        for l in l1:
            if(script.find(l)!=-1):
                    mallist.append(script)
                    malfile=True
    browserbool=False
    avgcpualert=False
    cpubool=False

    cpu_usage = psutil.cpu_percent()

    if(cpu_usage>85):
        avgcpualert=True
    
    print(cpu_usage)



    # if os.path.exists('C:/Users/malware-lab-windows/Desktop/FAST Eighth Semester/Fundamentals of Malware Analysis/Project/Process Hacker Processes.txt'):
    #     os.remove('C:/Users/malware-lab-windows/Desktop/FAST Eighth Semester/Fundamentals of Malware Analysis/Project/Process Hacker Processes.txt')

    # proc_exp.menu_select("File->Save")

    # proc_exp.send_keystrokes("^S")
    
    proc_exp.send_keystrokes("^S") # Save to file. If it is the first save, then it goes into save as scenario (handeled by i ==0), otherwise it saves to the same fil

    #break
    
    
    if i == 0:
        sleep(3)
        proc_exp.send_keystrokes("~") # Hit Enter to save file for the first time (Save As scenario)

    sleep(1)

    process_exp_out = pd.read_csv('E:\ProcessExplorer/Registry.txt', sep='\t')

    

    # process_hacker_out = pd.read_csv('Memory Compression.txt', sep='\t')

    process_exp_out = process_exp_out.dropna().reset_index(drop=True)

    remover_1 = process_exp_out["CPU"] == "Suspended"
    remover_1 = process_exp_out[remover_1]

    process_exp_out = process_exp_out.drop(remover_1.index).reset_index(drop=True)

    remover_2 = process_exp_out["CPU"] == "< 0.01"
    remover_2 = process_exp_out[remover_2]

    process_exp_out = process_exp_out.drop(remover_2.index).reset_index(drop=True)

    process_exp_out['CPU'] = process_exp_out['CPU'].astype(float)
    # print(process_exp_out.sort_values(by=['CPU'], inplace=True, ascending=False))

    sorted_on_cpu_usage = process_exp_out.sort_values(["CPU"], ascending=False).reset_index(drop=True)

    print(sorted_on_cpu_usage)


    
    print(sorted_on_cpu_usage.loc[0]['CPU']," ",sorted_on_cpu_usage.loc[0]['Process'])

    if sorted_on_cpu_usage.loc[0]['Process'].find("msedge.exe") != -1 or sorted_on_cpu_usage.loc[0]['Process'].find("firefox.exe") != -1:
        browserbool=True

    if(sorted_on_cpu_usage.loc[0]['CPU'] > 60):
        cpubool=True

    if((browserbool==True) and (cpubool==True) and (malfile==True) and (avgcpualert==True)):
        print("The process "+str(sorted_on_cpu_usage.loc[0]['Process'])+" with PID "+ str(sorted_on_cpu_usage.loc[0]['PID']) +" is CryptoMining") 
    else:
        print("Cryptomining not Found")
        print("CPUBOOL",cpubool)
        print("AVGCPU",avgcpualert)
        print("malfile",malfile)
        print("browserbool",browserbool)

    i += 1
    



    # break


    

   

     


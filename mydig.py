import dns.message
import dns.query
from datetime import datetime

#global flag to keep track of when to hard-end recursion
globaldone = 0

#Resolves the query for the domain through the name_servers, keeping track of the original time and original domain
def resolveQuery(domain, name_servers, time, original):
    global globaldone #We use global because sometimes there are separate paths, so a parameter based approach is flawed
    if(globaldone==1): #There is an issue when the recursion should end
        return
    for name_server in name_servers: #iterate through all the servers listed
        try: #try except to catch all errors
            response = dns.query.udp(domain, name_server, 1) #send a request and get a response
            if(response.rcode()!=0): #if the response fails, we should stop this branch
                print("Failed to get a response")
                return
            if(len(response.answer)==1):
                if("CNAME" in str(response.answer)): #if the answer is a cname we need a new request
                    request = dns.message.make_query(response.answer[0][0].to_text(), dns.rdatatype.A) #create new request
                    if(request.rcode() != 0): #failed to make query
                        print("Unable to create a request")
                        return
                    resolveQuery(request, root_servers, time, original) #resolve the cname through the root servers
                else: #the answer isn't a cname, so we are done
                    globaldone=1 #set flag, then we can print the program
                    print("QUESTION SECTION:")
                    print(original + ". " + str(response.question[0]).split(' ', 1)[1])
                    print("ANSWER SECTION:")
                    print(original + ". " + str(response.answer[0]).split(' ', 1)[1])
                    print("Query time: " + str(response.time*1000))
                    print("WHEN: " + str(time))
                    return #return > exit since exit() closes the window in IDLE, which I am using
            servers = [] #remember all the servers to pass down recursively
            for server in response.additional: #for the servers in additional
                if(" A " in str(server)): #if they are A(excludes AAAA/ipv6), add them
                    servers.append(str(server[0]))
            if(len(servers)==0): #if there were nothing, we wish to query from authority
                for server in response.authority:
                    request = dns.message.make_query(server[0].to_text(),dns.rdatatype.A) #create a new request for the name server
                    if(request.rcode() != 0): #failed to create a query
                        print("Could not create a query!")
                        exit()
                    resolveQuery(request, root_servers, time, original) #resolve the name server query from the root
            resolveQuery(domain, servers, time, original) #resolve the query with the new servers
        except dns.exception.Timeout: #if the error is a timeout
            print("Timeout occurred")
        except: #this is due to failure to parsing the response
            print("Unable to parse DNS response")

#Hardcoded root servers for the program to check
root_servers = ["198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13", "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53", "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42", "202.12.27.33"]

#Asks the user for the domain they wish to query
domain = input("Enter the domain you wish to resolve: ")


request = dns.message.make_query(domain, dns.rdatatype.A) #attempt to query
if(request.rcode() != 0): #failed to create a query
    print("Unable to create a request")
    exit()
resolveQuery(request, root_servers, datetime.now(), domain) #resolve the query

if(globaldone==0): #if after the whole query, we did not find an answer, we failed to connect
    print("Could not connect to server")

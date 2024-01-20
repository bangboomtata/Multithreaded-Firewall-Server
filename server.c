/* A threaded server in the internet domain using TCP
   The port number is passed as an argument */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <stdbool.h>

#define BUFFERLENGTH 512

#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(1);
};

struct threadArgs_t
{
    int newsockfd;
    int threadIndex;
};

int returnValue = 0;                             /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */

/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t
{
    pthread_t pthreadInfo;
    pthread_attr_t attributes;
    int status;
};
struct threadInfo_t *serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock = PTHREAD_RWLOCK_INITIALIZER;
pthread_rwlock_t ruleLock = PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;

struct firewallRule_t
{
    int ipaddr1[4];
    int ipaddr2[4];
    int port1;
    int port2;
};

struct queries_t
{
    int ip[4];
    int port;
    struct queries_t *next;
};

struct firewallRules_t
{
    struct firewallRule_t *rule;
    struct queries_t *query;
    struct firewallRules_t *next;
};

struct firewallRules_t *allRules = NULL;

/* Parse ip and port*/
char *parseIPaddress(int *ipaddr, char *text)
{
    char *oldPos, *newPos;
    long int addr;
    int i;

    oldPos = text;
    for (i = 0; i < 4; i++)
    {
        if (oldPos == NULL || *oldPos < '0' || *oldPos > '9')
        {
            return NULL;
        }
        addr = strtol(oldPos, &newPos, 10);
        if (newPos == oldPos)
        {
            return NULL;
        }
        if ((addr < 0) || addr > 255)
        {
            ipaddr[0] = -1;
            return NULL;
        }
        if (i < 3)
        {
            if ((newPos == NULL) || (*newPos != '.'))
            {
                ipaddr[0] = -1;
                return NULL;
            }
            else
                newPos++;
        }
        else if ((newPos == NULL) || ((*newPos != ' ') && (*newPos != '-')))
        {
            ipaddr[0] = -1;
            return NULL;
        }
        ipaddr[i] = addr;
        oldPos = newPos;
    }
    return newPos;
}

char *parsePort(int *port, char *text)
{
    char *newPos;

    if ((text == NULL) || (*text < '0') || (*text > '9'))
    {
        return NULL;
    }
    *port = strtol(text, &newPos, 10);
    if (newPos == text)
    {
        *port = -1;
        return NULL;
    }
    if ((*port < 0) || (*port > 65535))
    {
        *port = -1;
        return NULL;
    }
    return newPos;
}

/* Compare IP */
int compareIPAddresses(int *ipaddr1, int *ipaddr2)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if (ipaddr1[i] > ipaddr2[i])
        {
            return 1;
        }
        else if (ipaddr1[i] < ipaddr2[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Compare rules*/
int compareRules(struct firewallRule_t *rule1, struct firewallRule_t *rule2)
{
    if (compareIPAddresses(rule1->ipaddr1, rule2->ipaddr1) == 0 && compareIPAddresses(rule1->ipaddr2, rule2->ipaddr2) == 0 && rule1->port1 == rule2->port1 && rule1->port2 == rule2->port2)
    {
        return 0;
    }
    return -1;
}

struct firewallRule_t *readRule(char *line)
{
    struct firewallRule_t *newRule;
    char *pos;

    // parse IP addresses
    newRule = malloc(sizeof(struct firewallRule_t));
    pos = parseIPaddress(newRule->ipaddr1, line);
    if ((pos == NULL) || (newRule->ipaddr1[0] == -1))
    {
        free(newRule);
        return NULL;
    }
    if (*pos == '-')
    {
        // read second IP address
        pos = parseIPaddress(newRule->ipaddr2, pos + 1);
        if ((pos == NULL) || (newRule->ipaddr2[0] == -1))
        {
            free(newRule);
            return NULL;
        }

        if (compareIPAddresses(newRule->ipaddr1, newRule->ipaddr2) != -1)
        {
            free(newRule);
            return NULL;
        }
    }
    else
    {
        newRule->ipaddr2[0] = -1;
    }
    if (*pos != ' ')
    {
        free(newRule);
        return NULL;
    }
    else
        pos++;

    // parse ports
    pos = parsePort(&(newRule->port1), pos);
    if ((pos == NULL) || (newRule->port1 == -1))
    {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0'))
    {
        newRule->port2 = -1;
        return newRule;
    }
    if (*pos != '-')
    {
        free(newRule);
        return NULL;
    }

    pos++;
    pos = parsePort(&(newRule->port2), pos);
    if ((pos == NULL) || (newRule->port2 == -1))
    {
        free(newRule);
        return NULL;
    }
    if (newRule->port2 <= newRule->port1)
    {
        free(newRule);
        return NULL;
    }
    if ((*pos == '\n') || (*pos == '\0'))
    {
        return newRule;
    }
    free(newRule);
    return NULL;
}

struct firewallRules_t *addRule(struct firewallRule_t *rule)
{
    struct firewallRules_t *newRule;

    newRule = malloc(sizeof(struct firewallRules_t));
    newRule->rule = rule;
    newRule->next = allRules;
    newRule->query = NULL;
    return newRule;
}

/* Check */
bool checkIPAddress(int *ipaddr1, int *ipaddr2, int *ipaddr)
{
    int res;

    res = compareIPAddresses(ipaddr, ipaddr1);
    if (compareIPAddresses(ipaddr, ipaddr1) == 0)
    {
        return true;
    }
    else if (ipaddr2[0] == -1)
    {
        return false;
    }
    else if (res == -1)
    {
        return false;
    }
    else if (compareIPAddresses(ipaddr, ipaddr2) <= 0)
    {
        return true;
    }
    else
    {
        return false;
    }
}

int checkPort(int port1, int port2, int port)
{
    if (port == port1)
    {
        return 0;
    }
    else if (port < port1)
    {
        return -1;
    }
    else if (port2 == -1 || port > port2)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

void addQuery(struct firewallRules_t *tmpRules, int *ip, int port)
{
    struct queries_t *newQuery = malloc(sizeof(struct queries_t));

    newQuery->ip[0] = ip[0];
    newQuery->ip[1] = ip[1];
    newQuery->ip[2] = ip[2];
    newQuery->ip[3] = ip[3];
    newQuery->port = port;

    newQuery->next = tmpRules->query;
    tmpRules->query = newQuery;
}

void freeRule(struct firewallRules_t *allRules)
{
    struct queries_t *qurTmp = allRules->query;
    free(allRules->rule);
    while (qurTmp)
    {
        allRules->query = qurTmp->next;
        free(qurTmp);
        qurTmp = allRules->query;
    }
    free(allRules);
}

/* finds unused thread info slot; allocates more slots if necessary
   only called by main thread */
int findThreadIndex()
{
    int i, tmp;

    for (i = 0; i < noOfThreads; i++)
    {
        if (serverThreads[i].status == THREAD_AVAILABLE)
        {
            serverThreads[i].status = THREAD_IN_USE;
            return i;
        }
    }

    /* no available thread found; need to allocate more threads */
    pthread_rwlock_wrlock(&threadLock);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock(&threadLock);
    if (serverThreads == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    /* initialise thread status */
    for (tmp = i + 1; tmp < noOfThreads; tmp++)
    {
        serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

/* waits for threads to finish and releases resources used by the thread management functions. You don't need to modify this function */
void *waitForThreads(void *args)
{
    int i, res;
    while (1)
    {
        pthread_mutex_lock(&threadEndLock);
        pthread_cond_wait(&threadCond, &threadEndLock);
        pthread_mutex_unlock(&threadEndLock);

        pthread_rwlock_rdlock(&threadLock);
        for (i = 0; i < noOfThreads; i++)
        {
            if (serverThreads[i].status == THREAD_FINISHED)
            {
                res = pthread_join(serverThreads[i].pthreadInfo, NULL);
                if (res != 0)
                {
                    fprintf(stderr, "thread joining failed, exiting\n");
                    exit(1);
                }
                serverThreads[i].status = THREAD_AVAILABLE;
            }
        }
        pthread_rwlock_unlock(&threadLock);
    }
}

void printRules(char *buffer)
{
    struct firewallRules_t *ruleTmp = allRules;
    char ip1[20];
    char ip2[20];
    char port1[10];
    char port2[10];
    char queryIP[20];
    char queryPort[10];

    while (ruleTmp)
    {
        printf("ip1: %d.%d.%d.%d\n", ruleTmp->rule->ipaddr1[0], ruleTmp->rule->ipaddr1[1],
               ruleTmp->rule->ipaddr1[2], ruleTmp->rule->ipaddr1[3]);
        sprintf(ip1, "%d.%d.%d.%d", ruleTmp->rule->ipaddr1[0], ruleTmp->rule->ipaddr1[1],
                ruleTmp->rule->ipaddr1[2], ruleTmp->rule->ipaddr1[3]);

        sprintf(port1, " %d", ruleTmp->rule->port1);

        strcat(buffer, "Rule: ");
        strcat(buffer, ip1);

        if (ruleTmp->rule->ipaddr2[0] != -1)
        {
            sprintf(ip2, "-%d.%d.%d.%d", ruleTmp->rule->ipaddr2[0], ruleTmp->rule->ipaddr2[1],
                    ruleTmp->rule->ipaddr2[2], ruleTmp->rule->ipaddr2[3]);
            strcat(buffer, ip2);
        }

        strcat(buffer, port1);

        if (ruleTmp->rule->port2 != -1)
        {
            sprintf(port2, "-%d", ruleTmp->rule->port2);
            strcat(buffer, port2);
        }

        if (ruleTmp->next != NULL)
        {
            strcat(buffer, "\n");
        } 
        else if (ruleTmp->next == NULL && ruleTmp->query != NULL)
        {
            strcat(buffer, "\n");
        }

        struct queries_t *queryTmp = ruleTmp->query;

        while (queryTmp)
        {
            sprintf(queryIP, "%d.%d.%d.%d", queryTmp->ip[0], queryTmp->ip[1],
                    queryTmp->ip[2], queryTmp->ip[3]);

            sprintf(queryPort, " %d", queryTmp->port);

            strcat(buffer, "Query: ");
            strcat(buffer, queryIP);
            strcat(buffer, queryPort);

            if (ruleTmp->next != NULL)
            {
                strcat(buffer, "\n");
            }

            queryTmp = queryTmp->next;
        }

        ruleTmp = ruleTmp->next;
    }
}

bool ruleAccept(int *ip, int port)
{
    struct firewallRules_t *tmpRules = allRules;
    bool ruleAccepted = false;
    int res;

    while (tmpRules && !ruleAccepted)
    {
        res = checkPort(tmpRules->rule->port1, tmpRules->rule->port2, port);
        if (res == 0)
        {
            ruleAccepted = checkIPAddress(tmpRules->rule->ipaddr1, tmpRules->rule->ipaddr2, ip);
            if (ruleAccepted == true)
            {
                addQuery(tmpRules, ip, port);
                return true;
            }
        }
        tmpRules = tmpRules->next;
    }
    return false;
}

/* For each connection, this function is called in a separate thread. You need to modify this function. */
void *processRequest(void *args)
{
    struct threadArgs_t *threadArgs;
    char buffer[BUFFERLENGTH];
    int n;
    char userRule[100]; // combination of ip and port

    threadArgs = (struct threadArgs_t *)args;
    bzero(buffer, BUFFERLENGTH);
    n = read(threadArgs->newsockfd, buffer, BUFFERLENGTH - 1);

    if (n < 0)
        error("ERROR reading from socket");

    if (buffer[1] != ' ')
    {
        n = sprintf(buffer, "Illegal request");
        n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
    }
    else
    {
        strcpy(userRule, buffer + 2);

        if (n < 0)
            error("ERROR reading from socket");

        if (buffer[0] == 'A')
        {
            bzero(buffer, BUFFERLENGTH);
            struct firewallRule_t *newRule;
            newRule = readRule(userRule);

            if (newRule == NULL || newRule->ipaddr1[0] == -1)
            {
                n = sprintf(buffer, "Invalid rule");
                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
            else
            {
                pthread_rwlock_wrlock(&ruleLock);
                allRules = addRule(newRule);
                printf("ip1 add: %d.%d.%d.%d\n", allRules->rule->ipaddr1[0], allRules->rule->ipaddr1[1],
                       allRules->rule->ipaddr1[2], allRules->rule->ipaddr1[3]);
                pthread_rwlock_unlock(&ruleLock);
                n = sprintf(buffer, "Rule added");
                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
        }
        else if (buffer[0] == 'C')
        {
            bzero(buffer, BUFFERLENGTH);
            struct firewallRule_t *tmpRule;
            tmpRule = readRule(userRule);

            if (tmpRule == NULL || tmpRule->ipaddr1[0] == -1 || tmpRule->ipaddr2[0] != -1 || tmpRule->port2 != -1)
            {
                n = sprintf(buffer, "Illegal IP address or port specified");
                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
            else
            {
                pthread_rwlock_wrlock(&ruleLock);
                bool connectivity = ruleAccept(tmpRule->ipaddr1, tmpRule->port1);
                pthread_rwlock_unlock(&ruleLock);
                if (connectivity)
                {
                    n = sprintf(buffer, "Connection accepted");
                    n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
                }
                else
                {
                    n = sprintf(buffer, "Connection rejected");
                    n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
                }
            }
        }
        else if (buffer[0] == 'D')
        {
            // Check if the rule is valid
            struct firewallRule_t *deleteRule = readRule(userRule);
            bool ruleFounded = false;
            if (deleteRule == NULL && ruleFounded == false)
            {
                n = sprintf(buffer, "Rule invalid");
                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
            else
            {
                pthread_rwlock_wrlock(&ruleLock);
                // Search for the rule in stored rules
                struct firewallRules_t *prev = NULL;
                struct firewallRules_t *current = allRules;

                while (current != NULL && ruleFounded == false)
                {
                    // First rule found
                    if (compareRules(current->rule, deleteRule) == 0)
                    {
                        if (prev == NULL)
                        {
                            allRules = current->next;
                        }
                        else
                        {
                            prev->next = current->next;
                        }
                        freeRule(current);
                        ruleFounded = true;
                    }

                    if (!ruleFounded)
                    {
                        prev = current;
                        current = current->next;
                    }
                }
                pthread_rwlock_unlock(&ruleLock);
                
                if (ruleFounded)
                {
                    n = sprintf(buffer, "Rule deleted");
                }
                else
                {
                    n = sprintf(buffer, "Rule not found");
                }

                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
        }
        else if (buffer[0] == 'L')
        {
            bzero(buffer, BUFFERLENGTH);
            pthread_rwlock_rdlock(&ruleLock);
            if (allRules == NULL)
            {
                n = sprintf(buffer, "No rules");
                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
            else
            {
                printRules(buffer);
                n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
            }
            pthread_rwlock_unlock(&ruleLock);
        }
        else
        {
            bzero(buffer, BUFFERLENGTH);
            // Invalid command
            n = sprintf(buffer, "Illegal request");
            /* send the reply back */
            n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);

            if (n < 0)
                error("ERROR writing to socket");
        }
    }

    /* these two lines are required for proper thread termination */
    serverThreads[threadArgs->threadIndex].status = THREAD_FINISHED;
    pthread_cond_signal(&threadCond);

    close(threadArgs->newsockfd); /* important to avoid memory leak */
    free(threadArgs);
    pthread_exit(&returnValue);
}

int main(int argc, char *argv[])
{
    socklen_t clilen;
    int sockfd, portno;
    struct sockaddr_in6 serv_addr, cli_addr;
    int result;
    pthread_t waitInfo;
    pthread_attr_t waitAttributes;

    if (argc < 2)
    {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    /* create socket */
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(portno);

    /* bind it */
    if (bind(sockfd, (struct sockaddr *)&serv_addr,
             sizeof(serv_addr)) < 0)
        error("ERROR on binding");

    /* ready to accept connections */
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    /* create separate thread for waiting  for other threads to finish */
    if (pthread_attr_init(&waitAttributes))
    {
        fprintf(stderr, "Creating initial thread attributes failed!\n");
        exit(1);
    }

    result = pthread_create(&waitInfo, &waitAttributes, waitForThreads, NULL);
    if (result != 0)
    {
        fprintf(stderr, "Initial Thread creation failed!\n");
        exit(1);
    }

    /* now wait in an endless loop for connections and process them */
    while (1)
    {

        struct threadArgs_t *threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
        int threadIndex;

        threadArgs = malloc(sizeof(struct threadArgs_t));
        if (!threadArgs)
        {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(1);
        }

        /* waiting for connections */
        threadArgs->newsockfd = accept(sockfd,
                                       (struct sockaddr *)&cli_addr,
                                       &clilen);
        if (threadArgs->newsockfd < 0)
            error("ERROR on accept");

        /* create thread for processing of connection */
        threadIndex = findThreadIndex();
        threadArgs->threadIndex = threadIndex;
        if (pthread_attr_init(&(serverThreads[threadIndex].attributes)))
        {
            fprintf(stderr, "Creating thread attributes failed!\n");
            exit(1);
        }

        result = pthread_create(&(serverThreads[threadIndex].pthreadInfo), &(serverThreads[threadIndex].attributes), processRequest, (void *)threadArgs);
        if (result != 0)
        {
            fprintf(stderr, "Thread creation failed!\n");
            exit(1);
        }
    }
}

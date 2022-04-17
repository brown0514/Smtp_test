#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define MD3_NET_IMPLEMENTATION
#include "md3_net.h"
#include <stdbool.h>
#include <signal.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

// Thread num means max num client that can connect simultaneously.
#define MAX_THREAD_NUM          10
// Max attach file size to 16MB
#define MAX_ATTACH_FILE_SIZE    (1 << 24)
const char *CLIENT_LIST_PATH = "server/client_list.txt";
#define MAX_PACK_SIZE 1024

//global variables are for smooth operation between the split processes in both the client and the server sides
md3_net_socket_t remote_socket;
pid_t parentpid, pid;
bool Writing=false; //for the process to know that the client is currently typing an email
pthread_mutex_t lock[MAX_THREAD_NUM], g_lock;
pthread_t tid[MAX_THREAD_NUM];
char ClientEmailPerThread[MAX_THREAD_NUM][256];
md3_net_socket_t *SocketPerThread[MAX_THREAD_NUM];

typedef struct {
    char szToAddr[64];
    char szFromAddr[64];
    char szSubject[64];
    time_t tTimeStamp;
    size_t dwAttachFileSize;
    char szAttachFileName[64];
    char szExtension[16];
    char szContent[256];
    size_t readFlag;
} T_SmtpMessage;


#ifndef _countof
#define _countof(x) (sizeof(x) / sizeof(x[0]))
#endif

char* timeStamp(time_t rawtime){ //gives the current date and time
    struct tm * timeinfo;
    timeinfo = localtime ( &rawtime );
    char *timestamp;
    timestamp=asctime(timeinfo);
    return timestamp;
}

void to_lower_case(char* szText) {
    int nLen = strlen(szText);
    if (NULL == szText || 0 == nLen)
        return;
    int i;
    for (i = 0; i < nLen; i ++) {
        szText[i] = tolower((unsigned char) szText[i]);
    }
}

void sigstop(int signum){ //signal handler, sets the writing boolean to true and suspends the process
    Writing=true;
    raise(SIGSTOP);
}
void sigcont(int signum){ //signal handler, sets the writing boolean to false, used in the case when a hard reset is needed
    Writing=false;
}

md3_net_socket_t *client_socket;

void exiting_process(int signum) {
    md3_net_tcp_socket_send(client_socket, "=end=\0", 6);
}

// For receiving attach file...
int SocketFileReceive(md3_net_socket_t* remote_socket, char *szFileContent, size_t size)
{
    int total_received = 0;
    while(size > 0) {
        int sz = MAX_PACK_SIZE;
        if (sz > size) sz = size;
        int received = md3_net_tcp_socket_receive(remote_socket, szFileContent, sz);
        if (received) {
            total_received += received;
            szFileContent += received;
            size -= received;
        } else {
            break;
        }
    }
    return total_received;
}

// For sending attach file
int SocketFileSend(md3_net_socket_t* remote_socket, char *szFileContent, size_t size)
{
    int ret = 0;
    while(size > 0) {
        int sz = MAX_PACK_SIZE;
        if (sz > size) sz = size;
        if (0 != md3_net_tcp_socket_send(remote_socket, szFileContent, sz)) ret = 1;
        size -= sz;
        szFileContent += sz;
    }
    return ret;
}

// When a client connected, server will send new mails to the client.
char szNewInboxContent[1<<16];
void SendNewMailsToClient(md3_net_socket_t *remote_socket, char *ClientEmail, int pos) {
    char szInboxPath[256] = {};
    char szAttachFilePath[256] = {};
    snprintf(szInboxPath, 255, "server/%s/inbox/inbox.txt", ClientEmail);
    FILE* fInbox = fopen(szInboxPath, "r");
    if (fInbox) {
        T_SmtpMessage tSmtpMessage;
        char *p = szNewInboxContent;
        int total_size = 0;
        char* szAttachContent;
        while(1 == fread(&tSmtpMessage, sizeof(tSmtpMessage), 1, fInbox)) {
            if (tSmtpMessage.readFlag == 0) {
                pthread_mutex_lock(&lock[pos]);
                md3_net_tcp_socket_send(SocketPerThread[pos], &tSmtpMessage, sizeof(tSmtpMessage));
                if (tSmtpMessage.dwAttachFileSize) {
                    memset(szAttachFilePath, 0, sizeof(szAttachFilePath));
                    snprintf(szAttachFilePath, 255, "server/%s/inbox/%s_%ld_attach.%s",
                        tSmtpMessage.szToAddr,
                        tSmtpMessage.szSubject,
                        tSmtpMessage.tTimeStamp,
                        tSmtpMessage.szExtension);
                    FILE* fAttach = fopen(szAttachFilePath, "r");
                    if (fAttach) {
                        szAttachContent = calloc(tSmtpMessage.dwAttachFileSize, sizeof(char));
                        if (1 == fread(szAttachContent, tSmtpMessage.dwAttachFileSize, 1, fAttach)) {
                            SocketFileSend(SocketPerThread[pos], szAttachContent, tSmtpMessage.dwAttachFileSize);
                        }
                        free(szAttachContent);
                        fclose(fAttach);
                    }                   
                }
                pthread_mutex_unlock(&lock[pos]);
                tSmtpMessage.readFlag = 1;
            }
            memcpy(p, &tSmtpMessage, sizeof(tSmtpMessage));
            p += sizeof(tSmtpMessage);
            total_size += sizeof(tSmtpMessage);
        }
        fclose(fInbox);
        fInbox = fopen(szInboxPath, "w");
        if (fInbox) {
            fwrite(szNewInboxContent, total_size, 1, fInbox);
            fclose(fInbox);
        }
    }

}

void print(T_SmtpMessage *tSmtpMessage) {
    printf("\n");
    if (tSmtpMessage->readFlag == 0) printf("==*New Mail*==\n");
    printf("FROM: %s\n", tSmtpMessage->szFromAddr);
    printf("TO: %s\n", tSmtpMessage->szToAddr);
    printf("SUBJECT: %s\n", tSmtpMessage->szSubject);
    printf("BODY: %s\n", tSmtpMessage->szContent);
    if (tSmtpMessage->dwAttachFileSize) printf("ATTACH: one %s file attached\n", tSmtpMessage->szExtension);
    printf("TIME: %s\n", timeStamp(tSmtpMessage->tTimeStamp));
}

char IncomingMailFileName[256];
void sighand(int signum){ //signal handler. prompts a server process to send an email to its connected client
    char next[1024]="";
    FILE *IncomingMailFile;
    IncomingMailFile=fopen(IncomingMailFileName, "r"); //opens the file containing the emails addressed to the connected client for reading
    if (IncomingMailFile!=NULL){ //just checks if the opening was successful
        /*char * line = NULL;
        size_t len = 0;
        while (getline(&line, &len, IncomingMailFile) != -1) {
            strcat(next, line);
        }*/
        T_SmtpMessage tSmtpMessage = {};
        if (1 == fread(&tSmtpMessage, sizeof(tSmtpMessage), 1, IncomingMailFile)) {
            md3_net_tcp_socket_send(&remote_socket, &tSmtpMessage, sizeof(tSmtpMessage)); 
            if (tSmtpMessage.dwAttachFileSize) {
                char* szAttachContent = calloc(tSmtpMessage.dwAttachFileSize, 1);
                if (tSmtpMessage.dwAttachFileSize == fread(szAttachContent, 1, tSmtpMessage.dwAttachFileSize, IncomingMailFile)) {
                    md3_net_tcp_socket_send(&remote_socket, szAttachContent, tSmtpMessage.dwAttachFileSize); 
                }
            }
        }
        fclose(IncomingMailFile);
        //^^^ iterates over the lines in the file and adds them to a single string to send to the connected client
        //if (strcmp(next, "")!=0) md3_net_tcp_socket_send(&remote_socket, next, sizeof(next)); //checks if the email is actually empty or not, will not send if there is nothing there
        // delete old mail file.
        IncomingMailFile=fopen(IncomingMailFileName, "w");
        fclose(IncomingMailFile);
        unlink(IncomingMailFileName);
        //^^^ clears the email file once the email inside is sent to the client.
    }
    else printf("Error openeing file: %s\n", IncomingMailFileName);
}
int MailExtensionChecker(char* input){
    char checker[256];
    strcpy(checker, input);
    int len=strlen(checker);
    for (int i=0; i<len; i++){ //loop converts the input string into lowercase
        checker[i]=tolower((unsigned char) checker[i]);
    }
    if(strstr(checker, "@hotmail.com") || strstr(checker, "@gmail.com") || strstr(checker, "@live.com") || strstr(checker, "@outlook.com") || strstr(checker, "@ku.ac.ae")){
        int cnt=0; //if condition checks if the email extensions above are within the email provided
        for (int i=0; i<len; i++){ //the loop checks if there is more than one @ in the provided email, which is unacceptable
            if(checker[i]=='@') cnt++;
        }
        if (((int)(strchr(checker, '@')-checker)==0) || cnt>1) goto Invalid; //checks if the first character of the email is @ (as in the user just inputted @hotmail.com for example) or if there is indeed more than 1 @
        return 1; //returns 1 on success, as in the email is acceptable
    }
    else {
        Invalid:
        printf("Invalid Email and/or extension. please enter again: ");
        return 0; //returns 0 if the email violates the input rules
    }
}
bool CheckClientList(char *ClientEmail) {
    FILE* clientList=fopen(CLIENT_LIST_PATH,"r");
    bool found = false;
    if (clientList) {
        char * line = NULL;
        size_t len = 0;
        while (getline(&line, &len, clientList) != -1) {
            line[strlen(line)-1]='\0';
            if (strcmp(ClientEmail, line)==0)
            {
                found=true;
            }
            if (line) free(line);
            if(found) break;
        }
        fclose(clientList);
    }
    return found;
}

bool DeleteClientFromList(char * ClientEmail) {
    char FileContent[1024] = {};
    FILE* clientList=fopen(CLIENT_LIST_PATH,"r");
    bool found = false;
    int total_size = 0;
    if (clientList) {
        char * line = NULL;
        size_t len = 0;
        while (getline(&line, &len, clientList) != -1) {
            line[strlen(line)-1]='\0';
            if (strcmp(ClientEmail, line)==0)
            {
                found=true;
            } else {
                total_size += strlen(line) + 1;
                strcat(FileContent, line);
                strcat(FileContent, "\n");
            }
            if (line) free(line);
        }
        fclose(clientList);
    }
    if (found) {
        clientList=fopen(CLIENT_LIST_PATH, "w");
        fwrite(FileContent, total_size, 1, clientList);
    }
    return found;
}

char serverHostName[256];
// Because of 1st Advanced feature, I use multi-thread for multl-client.
void* start_service_for_one_client(void *arg) {
    int pos;
    memcpy(&pos, &arg, sizeof(int));
    FILE *Sender, *clientList, *fAttachFile; //directory to store the connected or available emails, "sender" file stores the email received by one client, in preparation to send it to the other client
    char ClientEmail[256] = {};
    char IncomingMailFileName[256] = {};
    md3_net_socket_t* remote_socket = SocketPerThread[pos];
    md3_net_tcp_socket_receive(remote_socket, &ClientEmail, sizeof(ClientEmail)); //this line is dedicated to receiving the client email that the client chose, and the server stores it in the directory and assigns it to the connected client
    printf("-----Assigned %s to %s\n",ClientEmail, serverHostName);
    ///
    to_lower_case(ClientEmail);

    SendNewMailsToClient(remote_socket, ClientEmail, pos);

    // create inbox and sent directories for each client in the server directory.
    char szClientEmailPath[256] = {};
    struct stat st = {0};
    snprintf(szClientEmailPath, 255, "server/%s", ClientEmail);
    if (stat(szClientEmailPath, &st) == -1) {
        mkdir(szClientEmailPath, 0777);
    }
    char szClientInboxPath[256] = {};
    snprintf(szClientInboxPath, 255, "server/%s/inbox", ClientEmail);
    if (stat(szClientInboxPath, &st) == -1) {
        mkdir(szClientInboxPath, 0777);
    }
    char szClientOutboxPath[256] = {};
    snprintf(szClientOutboxPath, 255, "server/%s/sent", ClientEmail);
    if (stat(szClientOutboxPath, &st) == -1) {
        mkdir(szClientOutboxPath, 0777);
    }
    pthread_mutex_lock(&g_lock);
    if (!CheckClientList(ClientEmail)) {
        clientList=fopen(CLIENT_LIST_PATH,"a");
        fprintf(clientList, "%s\n", ClientEmail);
        fclose(clientList);
    }
    pthread_mutex_unlock(&g_lock);
    ///^^ stores the connected clients email in the directory file after converting it to lowercase. lowercase conversion is for the sake of comparisons when validating the emails
    snprintf(IncomingMailFileName, 255, "server/%s/inbox/inbox.txt", ClientEmail);
/*    
    pid_t target;
    if (pid==0) {
         target=parentpid;
    }
    else {
        target=pid;
    }
*/
    //^^^ if and else statements above are to set the target process for the signals that will be sent in later parts.
    while (1) {
        T_SmtpMessage tRecvSmtpMessage = {};
        char* szAttachContent = NULL;
        bool error=false, found=false; //found is for validating the email the connected client is trying to send to
        int received;
        received = md3_net_tcp_socket_receive(remote_socket, &tRecvSmtpMessage, sizeof(tRecvSmtpMessage));
        if (strcmp(tRecvSmtpMessage.szToAddr, "=end=\0")==0) goto Done; //the client can choose to end the connection, which will send a message to the server. the server receives the message and acts accordingly
        if (received == 0) continue;
        if (received != sizeof(tRecvSmtpMessage)) error=true;
        if (tRecvSmtpMessage.dwAttachFileSize) {
            // received = md3_net_tcp_socket_receive(&remote_socket, &tRecvAttachFile, sizeof(tRecvAttachFile));
            //printf("tRecvAttachFile, %d == %d\n", sizeof(tRecvAttachFile), received);
            // if (received != sizeof(tRecvAttachFile)) error = true;
            szAttachContent = calloc(tRecvSmtpMessage.dwAttachFileSize, sizeof(char));
            received = SocketFileReceive(remote_socket, szAttachContent, tRecvSmtpMessage.dwAttachFileSize);
            //printf("attach content, %d == %d\n", tRecvAttachFile.dwFileSize, received);
            if (received != (tRecvSmtpMessage.dwAttachFileSize)) {
                printf("ERR: Attach file receive failed!\n");
                error = true;
            }
        }
        if (!error) {
            to_lower_case(tRecvSmtpMessage.szToAddr);
            found = CheckClientList(tRecvSmtpMessage.szToAddr);

            //^^^ validates the email in the TO field, if it is within the server directory then proceed normally. otherwise the found boolean with remain false, and an error message is sent back to the connected client instead
            if (!found) goto Error;
            if (MailExtensionChecker(tRecvSmtpMessage.szToAddr) == 0 || MailExtensionChecker(tRecvSmtpMessage.szFromAddr) == 0) {
                error = 1;
                goto Error;
            }
            char mailcheck[256] = {};
//          strcpy(mailcheck, incomingMail[0]); //copies the email in the TO field into another string
            snprintf(mailcheck, 255, "server/%s/inbox/inbox.txt", tRecvSmtpMessage.szToAddr);
            // this is to define which file to store the email into, to be forwarded by the server process connected to the second client
            md3_net_tcp_socket_send(remote_socket, "250 OK\0", 7); //at this point in the code the server has successfully received the email from its connected client. so it send a confirmation message
            Sender = fopen(mailcheck, "a"); //opens the file mentioned 2 lines ago for writing. if it does not exist then it will be created
/*          fprintf(Sender, "FROM: %s\n", incomingMail[1]);
            fprintf(Sender, "TO: %s\n", incomingMail[0]);
            fprintf(Sender, "SUBJECT: %s\n", incomingMail[2]);
            fprintf(Sender, "BODY: %s\n", incomingMail[3]);
            fprintf(Sender, "FROM: %s\n", tRecvSmtpMessage.szFromAddr);
            fprintf(Sender, "TO: %s\n", tRecvSmtpMessage.szToAddr);
            fprintf(Sender, "SUBJECT: %s\n", tRecvSmtpMessage.szSubject);
            fprintf(Sender, "BODY: %s\n", tRecvSmtpMessage.szContent);
            
            fprintf(Sender, "TIME: %s\n", timeStamp(tRecvSmtpMessage.tTimeStamp));
*/
            time_t tNow = time(NULL);
            char *timestamp=timeStamp(tNow);
            printf("Email received at server from %s at %s\n", serverHostName, timestamp);
            tRecvSmtpMessage.readFlag = 0;

            // Search ToAddr thread id...
            int to_id = -1;
            for (int i = 0; i < MAX_THREAD_NUM; i ++) {
                if (tid[i] != 0 && SocketPerThread[i] && strcmp(ClientEmailPerThread[i], tRecvSmtpMessage.szToAddr) == 0) {
                    to_id = i;
                    tRecvSmtpMessage.readFlag = 1;
                    break;
                }
            }
            fwrite(&tRecvSmtpMessage, sizeof(tRecvSmtpMessage), 1, Sender);
            if (tRecvSmtpMessage.dwAttachFileSize) {
                char szAttachFilePath[256] = {};
                snprintf(szAttachFilePath, 255, "server/%s/inbox/%s_%ld_attach.%s",
                    tRecvSmtpMessage.szToAddr,
                    tRecvSmtpMessage.szSubject,
                    tRecvSmtpMessage.tTimeStamp,
                    tRecvSmtpMessage.szExtension);
                fAttachFile = fopen(szAttachFilePath, "w");
                if (fAttachFile) {
                    fwrite(szAttachContent, tRecvSmtpMessage.dwAttachFileSize, 1, fAttachFile);
                    fclose(fAttachFile);
                }
            }
            fclose(Sender);
            //^^^ saves the email into the file
            printf("Echoing...\n");
            //sleep(1);
//          if(strcmp(incomingMail[0], ClientEmail)==0) kill(getpid(), SIGUSR1); //special case when the TO field contains the email of the sender
            
            pthread_mutex_lock(&lock[to_id]);
            md3_net_tcp_socket_send(SocketPerThread[to_id], &tRecvSmtpMessage, sizeof(tRecvSmtpMessage));
            if (tRecvSmtpMessage.dwAttachFileSize) {
                SocketFileSend(SocketPerThread[to_id], szAttachContent, tRecvSmtpMessage.dwAttachFileSize);
            }
            pthread_mutex_unlock(&lock[to_id]);
//          if(strcmp(tRecvSmtpMessage.szToAddr, ClientEmail)==0) kill(getpid(), SIGUSR1); //special case when the TO field contains the email of the sender
//          else kill(target, SIGUSR1); //sends signal to the server process connected to the second client to forward the email that was sent by the first client
        } else {
            Error:
            if (error) {
                pthread_mutex_lock(&lock[pos]);
                md3_net_tcp_socket_send(remote_socket, "501 ERROR\0", 10); //standard error in case there is an issue when receiving the email
                pthread_mutex_unlock(&lock[pos]);
            } else if (!found){ //sepcial error in case the email in the TO field does not match any email in the direcory
                printf("ERROR: Destination Email cannot be reached.\n");  
                pthread_mutex_lock(&lock[pos]);
                md3_net_tcp_socket_send(remote_socket, "550 ERROR\0", 10);
                pthread_mutex_unlock(&lock[pos]);
            }
        }
        if (tRecvSmtpMessage.dwAttachFileSize && szAttachContent) {
            free(szAttachContent);
        }
    }
    Done:
    DeleteClientFromList(ClientEmail);
//    clientList=fopen(CLIENT_LIST_PATH, "w");
//    fclose(clientList);
    //^^^ clears the directory file after the clients disconnect
    printf("Terminated connection with %s (%s)!\n",ClientEmail, serverHostName);
    md3_net_socket_close(remote_socket);
    tid[pos] = 0;
}

int run_server(unsigned short port) {

    // Mutex initializing...
    if  (pthread_mutex_init(&g_lock, NULL) != 0) {
        printf(" mutex init failed!\n");
        return 1;
    }
    for (int i = 0; i < MAX_THREAD_NUM; i ++) {
        if (pthread_mutex_init(&lock[i], NULL) != 0) {
            printf(" mutex init failed!\n");
            return 1;
        }
    }

    // Thread initializing...
    for (int i = 0; i < MAX_THREAD_NUM; i ++) {
        tid[i] = 0;
        memset(ClientEmailPerThread[i], 0, sizeof(ClientEmailPerThread[i]));
    }

    // signal(SIGUSR1, sighand); //sets the signal handler for SIGUSR1, whenever the process receives the SIGUSR1 signal it will execute the steps in the signal handler function defined above
    md3_net_init();
	const char *host;
	md3_net_address_t remote_addr;
    md3_net_socket_t socket;
    
    md3_net_tcp_socket_open(&socket, port, 0, 1);
    struct stat st = {0};
    if (stat("server", &st) == -1) {
        mkdir("server", 0777);
    }
    printf("Running echo server on port %d!\n", port);
    while(true) {
    	if (md3_net_tcp_accept(&socket, &remote_socket, &remote_addr)){
            printf("Failed to accept connection\n");
            continue;
         }
        host=md3_net_host_to_str(remote_addr.host);
        strcpy(serverHostName, host);
    	printf("Accepted connection from %s:%d\n", host, remote_addr.port);
        
        // Finding availabe Thread position...
        int pos;
        for (pos = 0; pos < MAX_THREAD_NUM; pos ++) {
            if (tid[pos] == 0) {
                break;
            }
        }
        if (pos == MAX_THREAD_NUM) {
            printf("Cannot connect to server because of busy.\n");
            printf("Terminated connection with %s:%d!\n",host, remote_addr.port);

            md3_net_socket_close(&remote_socket);
            continue;
        }
        SocketPerThread[pos] = &remote_socket;
        void *p;
        memcpy(&p, &pos, sizeof(void *));
        pthread_create(&(tid[pos]), NULL, &start_service_for_one_client, p);
    }

    return 0;
}

int run_client(const char *host, unsigned short port) {
    md3_net_init();

    md3_net_socket_t socket;
    md3_net_tcp_socket_open(&socket, 0, 0, 0);

    md3_net_address_t address;
    if (md3_net_get_address(&address, host, port) != 0) {
        printf("Error: %s\n", md3_net_get_error());

        md3_net_socket_close(&socket);
        md3_net_shutdown();

        return -1;
    }

    printf("Running client! Press Ctrl-C to exit.\n");
	
	if (md3_net_tcp_connect(&socket, address)) {
		printf("Failed to connect to %s:%d\n", host, port);
		return -1;
	}
	printf("Connected to %s:%d\n\n", host, port);
    client_socket = &socket;
    signal(SIGINT, exiting_process);
    signal(SIGKILL, exiting_process);
    signal(SIGSTOP, exiting_process);

    char ClientEmail[256];
    printf("Enter your email: ");
    do{
        fgets(ClientEmail, 256, stdin);
        ClientEmail[strlen(ClientEmail)-1]='\0';
    } while (!MailExtensionChecker(ClientEmail));
    //^^^ takes the clients email from keyboard input. has rules for proper email creation
    md3_net_tcp_socket_send(&socket, ClientEmail, sizeof(ClientEmail)); //once the use inputs a valid email it is sent to the server for its directory
    // Create directory for every client using the email address.
    struct stat st = {0};
    if (stat("client", &st) == -1) {
        mkdir("client", 0777);
    }
    char szClientEmailPath[256] = {};
    snprintf(szClientEmailPath, 255, "client/%s", ClientEmail);
    if (stat(szClientEmailPath, &st) == -1) {
        mkdir(szClientEmailPath, 0777);
    }
    // Create inbox and outbox directory in the email directory created above.
    char szInboxPath[256] = {};
    snprintf(szInboxPath, 255, "client/%s/inbox", ClientEmail);
    memset(&st, 0, sizeof(st));
    //printf("szInboxPath = %s\n", szInboxPath);
    //printf("%d\n", stat(szInboxPath, &st));
    if (stat(szInboxPath, &st) == -1) {
        mkdir(szInboxPath, 0777);
    }
    memset(&st, 0, sizeof(st));
    char szOutboxPath[256] = {};
    snprintf(szOutboxPath, 255, "client/%s/sent", ClientEmail);
    //printf("szOutboxPath = %s\n", szInboxPath);
    //printf("%d\n", stat(szOutboxPath, &st));
    if (stat(szOutboxPath, &st) == -1) {
        mkdir(szOutboxPath, 0777);
    }

    signal(SIGUSR1, sigstop); //sets the signal handler for SIGUSR1 to the sigstop function defined above
    signal(SIGUSR2, sigcont); //sets the signal handler for SIGUSR2 to the sigcont function defined above
    
    FILE *inboxFile = NULL, *outboxFile = NULL;
    pid = fork(); //splits the client process into two, once for sending emails and the other for receiving them
    char szMailTextPath[256] = {};
    if (pid!=0) { //parent process after the split will be used for sending
        char choice;
        while(1){
            printf("Would you like to view newmail, inbox, send an email, or exit? (N/I/S/E): ");
            scanf("%c", &choice);
            getchar();
            T_SmtpMessage tSmtpMessage = {};
            if (choice=='S'||choice=='s'){
                kill(pid, SIGUSR1); //sends a signal to the receiver process to suspend it and notify it that the user is typing an email
//              char email[4][256];
                do {
                    printf("Mail to: ");
                    fgets(tSmtpMessage.szToAddr, _countof(tSmtpMessage.szToAddr) - 1, stdin);
                    if (tSmtpMessage.szToAddr[strlen(tSmtpMessage.szToAddr) - 1] == '\n') {
                        tSmtpMessage.szToAddr[strlen(tSmtpMessage.szToAddr) - 1] = '\0';
                    } 
                    //fgets(email[0], 256, stdin);
                } while (!MailExtensionChecker(tSmtpMessage.szToAddr)); //loop makes sure user inputs valid email within the TO field
                //email[0][strlen(email[0]) - 1] = '\0';
                do {
                    printf("Mail From: ");
                    //fgets(email[1], 256, stdin);
                    fgets(tSmtpMessage.szFromAddr, _countof(tSmtpMessage.szFromAddr) - 1, stdin);
                    if (tSmtpMessage.szFromAddr[strlen(tSmtpMessage.szFromAddr) - 1] == '\n') {
                        tSmtpMessage.szFromAddr[strlen(tSmtpMessage.szFromAddr) - 1] = '\0';
                    } 
                } while (!MailExtensionChecker(tSmtpMessage.szFromAddr)); //loop makes sure user inputs valid email within the FROM field
//              email[1][strlen(email[1]) - 1] = '\0';
                printf("Subject: ");
//              fgets(email[2], 256, stdin);
//              email[2][strlen(email[2]) - 1] = '\0';
                fgets(tSmtpMessage.szSubject, _countof(tSmtpMessage.szSubject) - 1, stdin);
                // trim the last line character.
                if (tSmtpMessage.szSubject[strlen(tSmtpMessage.szSubject) - 1] == '\n') {
                    tSmtpMessage.szSubject[strlen(tSmtpMessage.szSubject) - 1] = '\0';
                } 
                printf("Body: ");

//              fgets(email[3], 256, stdin);
//              email[3][strlen(email[3]) - 1] = '\0';
                fgets(tSmtpMessage.szContent, _countof(tSmtpMessage.szContent) - 1, stdin);
                // trim the last line character.
                if (tSmtpMessage.szContent[strlen(tSmtpMessage.szContent) - 1] == '\n') {
                    tSmtpMessage.szContent[strlen(tSmtpMessage.szContent) - 1] = '\0';
                } 

                time_t tTimeStamp = time(NULL);
                tSmtpMessage.tTimeStamp = tTimeStamp;
                snprintf(szMailTextPath, 255, "%s/%s_%ld.txt", szOutboxPath, tSmtpMessage.szSubject, tTimeStamp);

                char szAttachFilePath[256] = {};
                FILE* fAttachFile = NULL;
                size_t dwAttachFileSize = 0;
                do {
                    printf("Attach file: (press enter if you want to skip.)\n");
                    fgets(szAttachFilePath, _countof(szAttachFilePath) - 1, stdin);
                    if (szAttachFilePath[strlen(szAttachFilePath) - 1] == '\n') {
                        szAttachFilePath[strlen(szAttachFilePath) - 1] = '\0';
                    }
                    if (strlen(szAttachFilePath) == 0) {
                        tSmtpMessage.dwAttachFileSize = 0;
                        break;
                    } else {
                        if (-1 == stat(szAttachFilePath, &st))
                            continue;
                        dwAttachFileSize = st.st_size;
                        if (MAX_ATTACH_FILE_SIZE <= dwAttachFileSize) {
                            printf("Attach file size must be smaller than %d megabytes\n", MAX_ATTACH_FILE_SIZE >> 20);
                            continue;
                        }
                        if (dwAttachFileSize) {
                            fAttachFile = fopen(szAttachFilePath, "r");
                            if (NULL == fAttachFile) {
                                printf("Attach file open failed.\n");
                                continue;
                            }
                        } else {
                            printf("Attach file size is 0.\n");
                            continue;
                        }
                        tSmtpMessage.dwAttachFileSize = dwAttachFileSize;
                        break;
                    }
                } while (1);

                char *szAttachFileContent = NULL;
                if (tSmtpMessage.dwAttachFileSize && fAttachFile) {
                    char szAttachSaveFilePath[256] = {};
                    char szAttachExtension[16] = {};
                    char* szTemp = strrchr(szAttachFilePath, '.');
                    if (szTemp) {
                        strncpy(szAttachExtension, szTemp + 1, _countof(szAttachExtension) - 1);
                        strncpy(tSmtpMessage.szExtension, szAttachExtension, _countof(tSmtpMessage.szExtension) - 1);
                        *szTemp = 0;
                        
                    } else {
                        //
                    }
                    strncpy(tSmtpMessage.szAttachFileName, szAttachFilePath, _countof(tSmtpMessage.szAttachFileName) - 1);
                    snprintf(szAttachSaveFilePath, 255, "%s/%s_%ld_attach.%s", szOutboxPath, tSmtpMessage.szSubject, tTimeStamp, szAttachExtension);
                    outboxFile=fopen(szAttachSaveFilePath, "a");
                    if (outboxFile) {
                        szAttachFileContent = calloc(dwAttachFileSize, sizeof(char));
                        if (NULL != szAttachFileContent)
                        if (dwAttachFileSize == fread(szAttachFileContent, sizeof(char), dwAttachFileSize, fAttachFile)) {
                            fwrite(szAttachFileContent, sizeof(char), dwAttachFileSize, outboxFile);
                            // tAttachFile.dwFileSize = dwAttachFileSize;
                        }
                        fclose(outboxFile);
                    }
                    fclose(fAttachFile);
                }
                outboxFile=fopen(szMailTextPath, "a");
                if (NULL != outboxFile) {
                    fwrite(&tSmtpMessage, sizeof(tSmtpMessage), 1, outboxFile);
                    fclose(outboxFile);
                }
                /*
                if (NULL != outboxFile) {
                    fprintf(outboxFile, "FROM: %s\n", tSmtpMessage.szFromAddr);
                    fprintf(outboxFile, "TO: %s\n", tSmtpMessage.szToAddr);
                    fprintf(outboxFile, "SUBJECT: %s\n", tSmtpMessage.szSubject);
                    fprintf(outboxFile, "BODY: %s\n", tSmtpMessage.szContent);
                    if (tSmtpMessage.dwAttachFileSize) fprintf(outboxFile, "ATTACH: one %s file attached\n", tSmtpMessage.szExtension);
                    fprintf(outboxFile, "TIME: %s\n", timeStamp(tTimeStamp));
                    fclose(outboxFile);
                }
                */
                //^^^ user creates the email which is then stored in the outbox file on the clients machine
                if (0 == md3_net_tcp_socket_send(&socket, &tSmtpMessage, sizeof(tSmtpMessage))) {
                    printf("\nEmail has been sent to the server.\n");
                }
                if (tSmtpMessage.dwAttachFileSize && szAttachFileContent) {
                    if (0 == SocketFileSend(&socket, szAttachFileContent, dwAttachFileSize)) {
                        printf("\n   And an attach file has been sent to the server.\n");
                    }
                    free(szAttachFileContent);
                }
                kill(pid, SIGCONT); //sends a signal to the receiving process that the user has stopped writing, and allows it to continue listening
                sleep(1);
                kill(pid, SIGUSR2); //forcibly notifies the receiving process that the user has stopped writing by setting the Writing boolean to false
            }
            else if (choice=='I'||choice=='i'){
                snprintf(szMailTextPath, 255, "%s/inbox.txt", szInboxPath);
                inboxFile=fopen(szMailTextPath, "r");
                if (NULL != inboxFile) {
                    char *p = szNewInboxContent;
                    int tot_sz = 0;
                    while(1 == fread(&tSmtpMessage, sizeof(tSmtpMessage), 1, inboxFile)) {
                        print(&tSmtpMessage);
                        tSmtpMessage.readFlag = 1;
                        memcpy(p, &tSmtpMessage, sizeof(tSmtpMessage));
                        p += sizeof(tSmtpMessage);
                        tot_sz += sizeof(tSmtpMessage);
                    }
                    fclose(inboxFile);
                    inboxFile = fopen(szMailTextPath, "w");
                    if (inboxFile) {
                        fwrite(szNewInboxContent, tot_sz, 1, inboxFile);
                        fclose(inboxFile);
                    }
                }
                //^^ prints out the clients inbox if they want
            }
            else if (choice=='N'||choice=='n'){
                snprintf(szMailTextPath, 255, "%s/inbox.txt", szInboxPath);
                inboxFile=fopen(szMailTextPath, "r");
                if (NULL != inboxFile) {
                    char *p = szNewInboxContent;
                    int tot_sz = 0;
                    while(1 == fread(&tSmtpMessage, sizeof(tSmtpMessage), 1, inboxFile)) {
                        if (tSmtpMessage.readFlag == 0) print(&tSmtpMessage);
                        tSmtpMessage.readFlag = 1;
                        memcpy(p, &tSmtpMessage, sizeof(tSmtpMessage));
                        p += sizeof(tSmtpMessage);
                        tot_sz += sizeof(tSmtpMessage);
                    }
                    fclose(inboxFile);
                    inboxFile = fopen(szMailTextPath, "w");
                    if (inboxFile) {
                        fwrite(szNewInboxContent, tot_sz, 1, inboxFile);
                        fclose(inboxFile);
                    }
                }
                //^^ prints out the clients inbox if they want
            }
            else if (choice=='E'||choice=='e'){
                md3_net_tcp_socket_send(&socket, "=end=\0", 6);
                break;
                //^^ client decides to end the session, which sends a message to the server notifying it
            }
            else {
                printf("Invalid input.\n");
            }
        }
    }
    else { //child process after split will be used for receiving
        bool error=false;
        int received, OK, ERROR, MAILERROR;
        char /*Inbox[1024], */Backlog[2048];
        memset(Backlog, 0, strlen(Backlog)); //zeros out the backlog after creating the string so problems do not appear
        while(1){
            T_SmtpMessage tSmtpMessage = {};
//          memset(Inbox, 0, strlen(Inbox)); //clears the inbox string after each iteration
            //received = md3_net_tcp_socket_receive(&socket, &Inbox, sizeof(Inbox)); //when receiving, the emails are received in one full string rather than separated fields as is the case when sending
            received = md3_net_tcp_socket_receive(&socket, &tSmtpMessage, sizeof(tSmtpMessage));
            if (!received) error=true;
            if (!error){
                OK=strcmp(tSmtpMessage.szToAddr, "250 OK\0");
                ERROR=strcmp(tSmtpMessage.szToAddr, "501 ERROR\0");
                MAILERROR=strcmp(tSmtpMessage.szToAddr, "550 ERROR\0");
                if (OK==0 || ERROR==0 || MAILERROR==0){ //the receiver process receives messages indiscriminately, so it can pick up the server reply. this is a check for that
                    time_t tNow = time(NULL);
                    char *timestamp = timeStamp(tNow);
                    printf("SERVER REPLY %s\n", tSmtpMessage.szToAddr);
                    if (OK==0) printf("Email received successfully at %s\n", timestamp);
                    else if (ERROR==0) printf("An error has occured while sending the email.\n\n");
                    else printf("Destination email could not be reached by server\n\n"); //else if not needed as the only option left after OK and ERROR is MAILERROR
                    if (Writing && strlen(Backlog)!=0){ //checks if the client was writing an email while it received one from the other client and if the backlog is empty
                        Writing=false; //if the process reaches this point it means that it was allowed to continue by the sender process, meaning the user has stopped writing
                        printf("\nYou have received mail(s) while sending!\n------\n");
                        printf("%s",Backlog);
                        printf("------\n");
                        ///^^ prints the backlog emails received while the user was writing an email
                    }
                }
                else {
                    snprintf(szMailTextPath, 255, "%s/inbox.txt", szInboxPath);
                    if (tSmtpMessage.dwAttachFileSize) {
                        char szAttachFilePath[256] = {};
                        char *szAttachContent = calloc(tSmtpMessage.dwAttachFileSize, 1);
                        snprintf(szAttachFilePath, 255, "%s/%s_%ld_attach.%s",
                            szInboxPath, tSmtpMessage.szSubject, tSmtpMessage.tTimeStamp, tSmtpMessage.szExtension);
                        FILE* fAttachFile = fopen(szAttachFilePath, "w");
                        received = SocketFileReceive(&socket, szAttachContent, tSmtpMessage.dwAttachFileSize);
                        if (received == tSmtpMessage.dwAttachFileSize) {
                            fwrite(szAttachContent, received, 1, fAttachFile);
                        }
                        fclose(fAttachFile);
                    }
                    if (tSmtpMessage.readFlag == 0) {
                        memset(Backlog, 0, sizeof(Backlog));
                        continue;
                    }
                    inboxFile=fopen(szMailTextPath, "a");
                    if (inboxFile) {
                        fwrite(&tSmtpMessage, sizeof(tSmtpMessage), 1, inboxFile);
                        fclose(inboxFile);
                    }
//                  printf("szMailTextPath = %s, inboxFile = %p, errno = %d, Inbox  =%s\n", szMailTextPath,  inboxFile, errno, Inbox);
                    if (Writing) { //if the user is writing at the time of receiving then the email is stored in the backlog instead
                        if(strlen(Backlog)!=0) strcat(Backlog, tSmtpMessage.szToAddr); //if there is already an email in the backlog, any more emails received are appended to the backlog
                        else strcpy(Backlog, tSmtpMessage.szToAddr); //if the backlog is empty then the received email is copied into it
                        continue; 
                        /*if the user is writing while receiving an email, then the server reply sent after they finish will be pushed behind the backlog, meaning the backlogged
                        emails will be printed before the server reply. the continue is here to prevent that*/
                    }
                    sleep(1);
                    printf("\nYou have received mail from %s!\n------\nSUBJECT: %s\n", tSmtpMessage.szFromAddr, tSmtpMessage.szSubject);
                    if (tSmtpMessage.dwAttachFileSize) printf("One %s file attached.\n", tSmtpMessage.szExtension);
                    printf("------\n");
                    printf("Would you like to view newmail, inbox, send an email, or exit? (N/I/S/E): ");
                    fflush(stdout);
                    //^^^if the user is not writing an email at the time of receiving then it will simply be printed onto the screen
                }
            }
            else {
                printf("Something went wrong; Client failed to receive message.\n");
                break;
            }
            memset(Backlog, 0, strlen(Backlog)); //clears the backlog once it is printed out
        }
    }
    printf("Done!\n");
    kill(pid, SIGTERM); //terminates the receiver process
    md3_net_socket_close(&socket);
    md3_net_shutdown();
    return 0;
}

int main(int argc, char **argv) {
    char hostname[_SC_HOST_NAME_MAX];
    gethostname(hostname, _SC_HOST_NAME_MAX);
    if (argc == 3 && strcmp(argv[1], "-server") == 0) {
        unlink("Directory.txt");
        printf("Mail Server starting on host: %s\n",hostname);
        printf("waiting to be contacted for transferring Mail... \n");
        return run_server((unsigned short) atoi(argv[2]));
        parentpid = getpid(); //saves the parent process ID for easy comminication between server processes later
        pid=fork(); //splits the server process into two, with each one connecting to a different client
        if (pid==0) return run_server((unsigned short) atoi(argv[3]));
        else return run_server((unsigned short) atoi(argv[2]));
    } else if (argc == 3 && strcmp(argv[1], "-client") == 0) {
        char szServerAddr[_SC_HOST_NAME_MAX];
        printf("Mail Client starting on host: %s \nType ip address of the mail server: ",hostname);
        fgets(szServerAddr, _SC_HOST_NAME_MAX, stdin);
        szServerAddr[strlen(szServerAddr)-1]='\0';
        return run_client(szServerAddr, (unsigned short) atoi(argv[2]));
    }

    printf("Usage: hala -server port1 port2 \nor hala -client port\n");

    return 0;
}

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

//global variables are for smooth operation between the split processes in both the client and the server sides
md3_net_socket_t remote_socket;
char IncomingMailFileName[256];
pid_t parentpid, pid;
bool Writing=false; //for the process to know that the client is currently typing an email


typedef struct {
    char szToAddr[64];
    char szFromAddr[64];
    char szSubject[64];
    time_t tTimeStamp;
    char szContent[256];
} T_SmtpMessage;

typedef struct {
    char szFileName[64];
    char szExtension[16];
    size_t dwFileSize;
    char szContent[];
} T_AttachmentFile;

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
void sighand(int signum){ //signal handler. prompts a server process to send an email to its connected client
    char next[1024]="";
    FILE *IncomingMailFile;
    IncomingMailFile=fopen(IncomingMailFileName, "r"); //opens the file containing the emails addressed to the connected client for reading
    if (IncomingMailFile!=NULL){ //just checks if the opening was successful
        char * line = NULL;
        size_t len = 0;
        while (getline(&line, &len, IncomingMailFile) != -1) {
            strcat(next, line);
        }
        fclose(IncomingMailFile);
        //^^^ iterates over the lines in the file and adds them to a single string to send to the connected client
        if (strcmp(next, "")!=0) md3_net_tcp_socket_send(&remote_socket, next, sizeof(next)); //checks if the email is actually empty or not, will not send if there is nothing there
        // delete old mail file.
        IncomingMailFile=fopen(IncomingMailFileName, "w");
        fclose(IncomingMailFile);
        unlink(IncomingMailFileName);
        //^^^ clears the email file once the email inside is sent to the client.
    }
    else printf("Error openeing file\n");
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
int run_server(unsigned short port) {
    signal(SIGUSR1, sighand); //sets the signal handler for SIGUSR1, whenever the process receives the SIGUSR1 signal it will execute the steps in the signal handler function defined above
    md3_net_init();
	const char *host;
	md3_net_address_t remote_addr;
    md3_net_socket_t socket;
    FILE *Sender, *Directory; //directory to store the connected or available emails, "sender" file stores the email received by one client, in preparation to send it to the other client

    md3_net_tcp_socket_open(&socket, port, 0, 1);
    printf("Running echo server on port %d!\n", port);
	if (md3_net_tcp_accept(&socket, &remote_socket, &remote_addr)) printf("Failed to accept connection\n");
    host=md3_net_host_to_str(remote_addr.host);
	printf("Accepted connection from %s:%d\n", host, remote_addr.port);

    char ClientEmail[256];
    md3_net_tcp_socket_receive(&remote_socket, &ClientEmail, sizeof(ClientEmail)); //this line is dedicated to receiving the client email that the client chose, and the server stores it in the directory and assigns it to the connected client
    printf("-----Assigned %s to %s\n",ClientEmail, host);
    ///
//  int EmailLen=strlen(ClientEmail);
//  for (int i=0; i<EmailLen; i++) ClientEmail[i]=tolower((unsigned char) ClientEmail[i]);
    to_lower_case(ClientEmail);
    Directory=fopen("Directory.txt","a");
    fprintf(Directory, "%s\n", ClientEmail);
    fclose(Directory);
    ///^^ stores the connected clients email in the directory file after converting it to lowercase. lowercase conversion is for the sake of comparisons when validating the emails
    strcpy(IncomingMailFileName, ClientEmail); //copies the email into another string
    strcat(IncomingMailFileName, ".txt"); //appends .txt to the email, this is for definig which file the server should open to accept and forward emails directed to its own connected client

//  char incomingMail[4][256];
    pid_t target;
    if (pid==0) {
         target=parentpid;
    }
    else {
        target=pid;
    }
    //^^^ if and else statements above are to set the target process for the signals that will be sent in later parts.
    while (1) {
        T_SmtpMessage tRecvSmtpMessage = {};
        bool error=false, found=false; //found is for validating the email the connected client is trying to send to
        int received;
/*      for (int i=0; i<4; i++) {
            received = md3_net_tcp_socket_receive(&remote_socket, &incomingMail[i], sizeof(incomingMail[i]));
            if (!received) error=true;
            else if (strcmp(incomingMail[i], "=end=\0")==0) goto Done; //the client can choose to end the connection, which will send a message to the server. the server receives the message and acts accordingly
        } ///^^ for loop accepts 4 tcp messages from its client, each one representing a field (to, from, subject, body)
*/

        received = md3_net_tcp_socket_receive(&remote_socket, &tRecvSmtpMessage, sizeof(tRecvSmtpMessage));
        if (strcmp(tRecvSmtpMessage.szToAddr, "=end=\0")==0) goto Done; //the client can choose to end the connection, which will send a message to the server. the server receives the message and acts accordingly
        if (received == 0) continue;
        if (received != sizeof(tRecvSmtpMessage)) error=true;
        if (!error) {
//          EmailLen=strlen(incomingMail[0]); //incomingMail[0] represents the TO field of the email
//          for (int i=0; i<EmailLen; i++) incomingMail[0][i]=tolower((unsigned char) incomingMail[0][i]); //loop converts it to lower case for validating
            to_lower_case(tRecvSmtpMessage.szToAddr);
            char * line = NULL;
            size_t len = 0;
            ///
            Directory=fopen("Directory.txt","r");
            while (getline(&line, &len, Directory) != -1) {
                line[strlen(line)-1]='\0';
//              if (strcmp(incomingMail[0], line)==0)
                if (strcmp(tRecvSmtpMessage.szToAddr, line)==0)
                {
                    found=true;
                    break;
                }
            }
            fclose(Directory);
            //^^^ validates the email in the TO field, if it is within the server directory then proceed normally. otherwise the found boolean with remain false, and an error message is sent back to the connected client instead
            if (!found) goto Error;
            char mailcheck[256] = {};
//          strcpy(mailcheck, incomingMail[0]); //copies the email in the TO field into another string
            strcpy(mailcheck, tRecvSmtpMessage.szToAddr); //copies the email in the TO field into another string
            strcat(mailcheck, ".txt"); //appends .txt to the email, this is to define which file to store the email into, to be forwarded by the server process connected to the second client
            md3_net_tcp_socket_send(&remote_socket, "250 OK\0", 7); //at this point in the code the server has successfully received the email from its connected client. so it send a confirmation message
            Sender = fopen(mailcheck, "w"); //opens the file mentioned 2 lines ago for writing. if it does not exist then it will be created
/*          fprintf(Sender, "FROM: %s\n", incomingMail[1]);
            fprintf(Sender, "TO: %s\n", incomingMail[0]);
            fprintf(Sender, "SUBJECT: %s\n", incomingMail[2]);
            fprintf(Sender, "BODY: %s\n", incomingMail[3]);
*/          fprintf(Sender, "FROM: %s\n", tRecvSmtpMessage.szFromAddr);
            fprintf(Sender, "TO: %s\n", tRecvSmtpMessage.szToAddr);
            fprintf(Sender, "SUBJECT: %s\n", tRecvSmtpMessage.szSubject);
            fprintf(Sender, "BODY: %s\n", tRecvSmtpMessage.szContent);
            time_t tNow = time(NULL);
            char *timestamp=timeStamp(tNow);
            printf("Email received at server from %s at %s\n", host, timestamp);
            fprintf(Sender, "TIME: %s\n", timeStamp(tRecvSmtpMessage.tTimeStamp));
            fclose(Sender);
            //^^^ saves the email into the file
            printf("Echoing...\n");
//          if(strcmp(incomingMail[0], ClientEmail)==0) kill(getpid(), SIGUSR1); //special case when the TO field contains the email of the sender
            if(strcmp(tRecvSmtpMessage.szToAddr, ClientEmail)==0) kill(getpid(), SIGUSR1); //special case when the TO field contains the email of the sender
            else kill(target, SIGUSR1); //sends signal to the server process connected to the second client to forward the email that was sent by the first client
            }
        
        else {
            Error:
            if (error) md3_net_tcp_socket_send(&remote_socket, "501 ERROR\0", 10); //standard error in case there is an issue when receiving the email
            else if (!found){ //sepcial error in case the email in the TO field does not match any email in the direcory
                printf("ERROR: Destination Email cannot be reached.\n");  
                md3_net_tcp_socket_send(&remote_socket, "550 ERROR\0", 10);
            }
        }
    }
    Done:
    Directory=fopen("Directory.txt", "w");
    fclose(Directory);
    //^^^ clears the directory file after the clients disconnect
    printf("Terminated connection with %s (%s)!\n",ClientEmail, host);
    md3_net_socket_close(&remote_socket);
    md3_net_socket_close(&socket);
    
    md3_net_shutdown();

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
    if (stat(ClientEmail, &st) == -1) {
        mkdir(ClientEmail, 0777);
    }
    // Create inbox and outbox directory in the email directory created above.
    char szInboxPath[256] = {};
    snprintf(szInboxPath, 255, "%s/inbox", ClientEmail);
    memset(&st, 0, sizeof(st));
    printf("szInboxPath = %s\n", szInboxPath);
    printf("%d\n", stat(szInboxPath, &st));
    if (stat(szInboxPath, &st) == -1) {
        mkdir(szInboxPath, 0777);
    }
    memset(&st, 0, sizeof(st));
    char szOutboxPath[256] = {};
    snprintf(szOutboxPath, 255, "%s/outbox", ClientEmail);
    printf("szOutboxPath = %s\n", szInboxPath);
    printf("%d\n", stat(szOutboxPath, &st));
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
            printf("Would you like to view your inbox, send an email, or exit? (I/S/E): ");
            scanf("%c", &choice);
            getchar();
            if (choice=='S'||choice=='s'){
                kill(pid, SIGUSR1); //sends a signal to the receiver process to suspend it and notify it that the user is typing an email
                T_SmtpMessage tSmtpMessage = {};
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
                outboxFile=fopen(szMailTextPath, "a");
                if (NULL != outboxFile) {
/*                  fprintf(outboxFile, "FROM: %s\n", email[1]);
                    fprintf(outboxFile, "TO: %s\n", email[0]);
                    fprintf(outboxFile, "SUBJECT: %s\n", email[2]);
                    fprintf(outboxFile, "BODY: %s\n", email[3]);
*/                  
                    fprintf(outboxFile, "FROM: %s\n", tSmtpMessage.szFromAddr);
                    fprintf(outboxFile, "TO: %s\n", tSmtpMessage.szToAddr);
                    fprintf(outboxFile, "SUBJECT: %s\n", tSmtpMessage.szSubject);
                    fprintf(outboxFile, "BODY: %s\n", tSmtpMessage.szContent);
                    fprintf(outboxFile, "TIME: %s\n", timeStamp(tTimeStamp));
                    fclose(outboxFile);
                }
                //^^^ user creates the email which is then stored in the outbox file on the clients machine
/*              for (int i=0; i<4; i++){
                    md3_net_tcp_socket_send(&socket, email[i], sizeof(email[i]));
                } //loop sends all the fields of the email to the server
*/
                md3_net_tcp_socket_send(&socket, &tSmtpMessage, sizeof(tSmtpMessage));
                printf("\n////Sending...\n");
                kill(pid, SIGCONT); //sends a signal to the receiving process that the user has stopped writing, and allows it to continue listening
                sleep(1);
                kill(pid, SIGUSR2); //forcibly notifies the receiving process that the user has stopped writing by setting the Writing boolean to false
            }
            else if (choice=='I'||choice=='i'){
                snprintf(szMailTextPath, 255, "%s/inbox.txt", szInboxPath);
                inboxFile=fopen(szMailTextPath, "r");
                if (NULL != inboxFile) {
                    char * line = NULL;
                    size_t len = 0;
                    while (getline(&line, &len, inboxFile) != -1) {
                        printf("%s",line);
                    }
                    fclose(inboxFile);
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
        char Inbox[1024], Backlog[2048];
        memset(Backlog, 0, strlen(Backlog)); //zeros out the backlog after creating the string so problems do not appear
        while(1){
            memset(Inbox, 0, strlen(Inbox)); //clears the inbox string after each iteration
            received = md3_net_tcp_socket_receive(&socket, &Inbox, sizeof(Inbox)); //when receiving, the emails are received in one full string rather than separated fields as is the case when sending
            if (!received) error=true;
            if (!error){
                OK=strcmp(Inbox, "250 OK\0");
                ERROR=strcmp(Inbox, "501 ERROR\0");
                MAILERROR=strcmp(Inbox, "550 ERROR\0");
                if (OK==0 || ERROR==0 || MAILERROR==0){ //the receiver process receives messages indiscriminately, so it can pick up the server reply. this is a check for that
                    time_t tNow = time(NULL);
                    char *timestamp = timeStamp(tNow);
                    printf("SERVER REPLY %s\n", Inbox);
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
                    inboxFile=fopen(szMailTextPath, "w");
//                  printf("szMailTextPath = %s, inboxFile = %p, errno = %d, Inbox  =%s\n", szMailTextPath,  inboxFile, errno, Inbox);
                    if (NULL != inboxFile) {
                        fprintf(inboxFile, "%s\n", Inbox);
                        fclose(inboxFile);
                    }
                    if (Writing) { //if the user is writing at the time of receiving then the email is stored in the backlog instead
                        if(strlen(Backlog)!=0) strcat(Backlog, Inbox); //if there is already an email in the backlog, any more emails received are appended to the backlog
                        else strcpy(Backlog, Inbox); //if the backlog is empty then the received email is copied into it
                        continue; 
                        /*if the user is writing while receiving an email, then the server reply sent after they finish will be pushed behind the backlog, meaning the backlogged
                        emails will be printed before the server reply. the continue is here to prevent that*/
                    }
                    sleep(1);
                    printf("\nYou have received mail!\n------\n");
                    printf("%s",Inbox);
                    printf("------\n");
                    printf("Would you like to view your inbox, send an email, or exit? (I/S/E): ");
                    fflush(stdout);
                    //^^^if the user is not writing an email at the time of receiving then it will simply be printed onto the screen
                }
            }
            else printf("Something went wrong; Client failed to receive message.\n");
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
    if (argc == 4 && strcmp(argv[1], "-server") == 0) {
        printf("Mail Server starting on host: %s\n",hostname);
        printf("waiting to be contacted for transferring Mail... \n");
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


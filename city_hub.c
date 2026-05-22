//un pipe este un canal de comunicare intre 2

#define _POSIX_C_SOURCE 200809L
 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
 
#define MAX      200
#define MAX_PATH 300
#define PID_FILE ".monitor_pid"
 
void calculate_scores(int nr_districte, char **districte)
{
  printf("=== Raport Workload ===\n\n");
 
  for (int i = 0; i < nr_districte; i++) {
    //facem pipeul pt 2 districte.
    int fd[2];
    if (pipe(fd) == -1) {
      perror("Eroare pipe");
      continue;
    }
 
    pid_t pid = fork(); //practic dublura pt pid

  
 
    if (pid == 0) {
      // leg dintre COPIL - scorer 
 
      // Inchidem capatul de citire - copilul doar scrie
      //Un proces nu poate să scrie și să citească simultan din același pipe în mod eficient (s-ar bloca la scriere înainte să ajungă la linia de citire).
      close(fd[0]);
 
      // dup2 redirecteaza stdout catre capatul de scriere al pipe-ului	 tot ce scorer-ul scrie cu printf() ajunge in pipe, nu pe ecran 
      dup2(fd[1], STDOUT_FILENO);
      close(fd[1]);  // inchidem originalul dupa redirectare 
 
      // Rulam scorer-ul cu numele districtului ca argument 
      char *args[] = {"./scorer", districte[i], NULL};
      execvp("./scorer", args);
 
      // Daca ajungem aici, execvp a esuat 
      perror("Eroare execvp scorer");
      //_exit(1) e mai okay decat exit(1) in cazul asta ca nu icearca sa goleasca bifferele in copil ceea ce e 
      _exit(1);
 
    } else if (pid > 0) {
      //---- PARINTE - city_hub ---- 
 
      //Inchidem capatul de scriere - parintele doar citeste 
      close(fd[1]);
 
      // Citim rezultatul din pipe linie cu linie 
      char buf[1024];
      ssize_t n; //signed cu semn pe biti folosum ssize_T
 
      // read() citeste blocuri de bytes din pipe 
      while ((n = read(fd[0], buf, sizeof(buf) - 1)) > 0) {
	buf[n] = '\0';
	//Afisam ce am primit 
	printf("%s", buf);
      }
      close(fd[0]);
 
      // Asteptam scorerul sa termine 
      wait(NULL);
 
      // Linie de separare intre districte 
      printf("\n");
 
    } else {
      perror("Eroare fork");
    }
  }
 
  printf("=== Sfarsit Raport ===\n");
}

void start_monitor()
{
    // Verificam DIRECT in city_hub daca monitorul ruleaza deja
    // daca .monitor_pid exista, monitorul deja ruleaza
    struct stat st;
    if (stat(PID_FILE, &st) == 0) {
        char buf_pid[32];
        memset(buf_pid, 0, sizeof(buf_pid));
        int fd_pid = open(PID_FILE, O_RDONLY);
        if (fd_pid != -1) {
            read(fd_pid, buf_pid, sizeof(buf_pid) - 1);
            close(fd_pid);
        }
        printf("ERROR: Monitor deja ruleaza cu PID=%s\n", buf_pid);
        return; // iesim fara sa cream hub_mon
    }

    // Cream pipe-ul inainte de fork
    // fd[0] = capatul de citire
    // fd[1] = capatul de scriere
    int fd[2];
    if (pipe(fd) == -1) {
        perror("Eroare pipe");
        return;
    }

    // fork() pentru hub_mon
    pid_t pid_hub_mon = fork();

    if (pid_hub_mon == 0) {
        // COPIL = hub_mon
        // hub_mon nu scrie in pipe - inchide capatul de scriere
        close(fd[1]);

        // fork() pentru monitor_reports
        pid_t pid_mon = fork();

        if (pid_mon == 0) {
            // NEPOT = monitor_reports
            // redirectam stdout-ul monitorului catre pipe cu dup2
            // tot ce monitor scrie cu printf ajunge in pipe
            dup2(fd[1], STDOUT_FILENO);
            close(fd[0]); // monitorul nu citeste din pipe

            char *args[] = {"./monitor_reports", NULL};
            execvp("./monitor_reports", args);

            // daca ajungem aici execvp a esuat
            perror("Eroare execvp monitor_reports");
            _exit(1);

        } else if (pid_mon > 0) {
            // hub_mon citeste din pipe mesajele monitorului si le afiseaza
            close(fd[1]); // hub_mon nu scrie

            char buf[256];
            ssize_t n;
            while ((n = read(fd[0], buf, sizeof(buf) - 1)) > 0) {
                buf[n] = '\0';
                printf("%s", buf);
                fflush(stdout);
            }
            close(fd[0]);
            wait(NULL); // asteptam monitorul sa termine

        } else {
            perror("Eroare fork monitor");
            close(fd[0]);
            _exit(1);
        }

        _exit(0);

    } else if (pid_hub_mon > 0) {
        // PARINTE = city_hub
        // city_hub nu foloseste pipe-ul - inchidem ambele capete
        close(fd[0]);
        close(fd[1]);
        printf("Monitor pornit in fundal (hub_mon PID=%d)\n", pid_hub_mon);

    } else {
        perror("Eroare fork hub_mon");
    }
}


void afiseaza_comenzi()
{
    printf("Comenzi disponibile:\n");
    printf("  start_monitor\n");
    printf("  calculate_scores <district1> [district2 ...]\n");
    printf("  exit\n");
}
 
int main()
{
    printf("=== city_hub - Interfata de management ===\n");
    afiseaza_comenzi();
 
    char linie[1024];
 
    //citim comenzi de la tastatura 
    while (1) {
        printf("\ncity_hub> ");
        fflush(stdout);
 
        // Citim o linie de la tastatura 
        if (fgets(linie, sizeof(linie), stdin) == NULL) {
            printf("Iesire city_hub.\n");
            break;
        }
 
        //Eliminam newline-ul de la sfarsit 
        size_t len = strlen(linie);
        if (len > 0 && linie[len - 1] == '\n')
            linie[len - 1] = '\0';
 
        //Ignoram liniile goale 
        if (strlen(linie) == 0)
	  continue;
 
        // Parsam comanda - primul cuvant e comanda, restul sunt argumente 
        char *token = strtok(linie, " ");
        if (!token)
	  continue;
 
        if (strcmp(token, "exit") == 0) {
            printf("Iesire city_hub.\n");
            break;
 
        } else if (strcmp(token, "start_monitor") == 0) {
            start_monitor();
 
        } else if (strcmp(token, "calculate_scores") == 0) {
	  //Colectam toate districtele din argumente 
            char *districte[50];
            int nr = 0;
 
            char *arg = strtok(NULL, " ");
            while (arg != NULL && nr < 50) {
                districte[nr++] = arg;
                arg = strtok(NULL, " ");
            }
 
            if (nr == 0) {
                fprintf(stderr, "EROARE: calculate_scores necesita cel putin un district.\n");
            } else {
                calculate_scores(nr, districte);
            }
 
        } else {
            fprintf(stderr, "Comanda necunoscuta: '%s'\n", token);
            afiseaza_comenzi();
        }
    }
 
    return 0;
}

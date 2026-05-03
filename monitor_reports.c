#include<stdio.h>
#include<string.h>
#include <unistd.h> // luam getpid()
#include <signal.h>
#include <fcntl.h> // biblioteca ce include  O_WRONLY | O_CREAT | O_TRUNC
#include <sys/stat.h>
#include <sys/types.h> // pt orice functie ce ar fi definita de sistem ca int folosim pid_t

// Fisierul unde salvam PID-ul monitorului
#define PID_FILE ".monitor_pid"
#define _POSIX_C_SOURCE 200809L //îi spune compilatorului să activeze funcțiile din standardul POSIX 2008. functti ca sigation

void handler_sigusr1(int sig)
{
  (void)sig; //evitam warrningurile ca nu e folosit param sig
  const char *msg = "[MONITOR] Raport nou adaugat intr-un district!\n";
  write(STDOUT_FILENO, msg, strlen(msg));
}


void handler_sigint(int sig)
{
    (void)sig; 

    const char *msg = "[MONITOR] SIGINT primit. Monitor oprit.\n";
    write(STDOUT_FILENO, msg, strlen(msg));

    // Stergem fisierul .monitor_pid la oprire
    // unlink() e async-signal-safe
    unlink(PID_FILE);
    // _exit() e async-signal-safe, exit() nu este
    _exit(0);
}

void creaza_pid_file()
{
    // O_WRONLY - doar scriere
    // O_CREAT  - creaza daca nu exista
    // O_TRUNC  - suprascrie 
    int fd = open(PID_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("Eroare la crearea .monitor_pid");
        exit(EXIT_FAILURE);
    }

    
    pid_t pid = getpid();

    // Convertim PID-ul din numar in sir de caractere
    char buf[32];
    snprintf(buf, sizeof(buf), "%d\n", pid);

    // Scriem PID-ul in fisier
    write(fd, buf, strlen(buf));
    close(fd);

    printf("[MONITOR] Pornit cu PID=%d. Fisier '%s' creat.\n", pid, PID_FILE);
}

void inregistreaza_semnale()
{
    struct sigaction sa;
    sa.sa_handler = handler_sigusr1; // functia apelata la semnal
    sigemptyset(&sa.sa_mask);        // nu blocam alte semnale in handler
    sa.sa_flags = 0;                 // fara optiuni speciale
    if (sigaction(SIGUSR1, &sa, NULL) == -1) {
        perror("Eroare sigaction SIGUSR1");
        exit(EXIT_FAILURE);
    }

    sa.sa_handler = handler_sigint;  // functia apelata la Ctrl+C
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("Eroare sigaction SIGINT");
        exit(EXIT_FAILURE);
    }
}

int main()
{
    printf("[MONITOR] Pornire monitor_reports...\n");
    creaza_pid_file();
    inregistreaza_semnale();

    printf("[MONITOR] Astept semnale... (SIGUSR1 = raport nou, SIGINT = oprire)\n");

    // asteptam semnale
    // pause() pune procesul sa doarma pana vine orice semnal
    // dupa ce handlerul se executa, pause() se intoarce si
    // bucla while il apeleaza din nou
    while (1) {
        pause();
    }
    return 0;
}

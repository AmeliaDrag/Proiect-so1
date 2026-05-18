#define _POSIX_C_SOURCE 200809L // in teorie pt chestile alea, dar aici nu avem gen sit

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

//structura trb sa fie la fel ca in proiect1.c ca sa o pot citi

typedef struct {
    int    report_id;
    char   inspector_name[100];
    float  lat;
    float  longi;
    char   category[50];
    int    severity_level;
    time_t Timestamp;
    char   description_text[100];
} Report;

#define MAX_INSPECTORS 50
#define MAX_NAME       100

// Structura pentru a tine scorul unui inspector 
typedef struct {
    char name[MAX_NAME];
    int  workload;  
} InspectorScore;

/*
  scorer primeste ca argument calea catre district:
  ./scorer downtown
 
  Citeste reports.dat din acel district, calculeaza suma
  severitarilor per inspector si scrie rezultatul la stdout.
  city_hub redirecteaza stdout-ul cu dup2() catre un pipe.
 */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Utilizare: %s <district>\n", argv[0]);
        return 1;
    }

    const char *district = argv[1];
    char path_reports[300];
    snprintf(path_reports, sizeof(path_reports), "%s/reports.dat", district);

    // Deschidem fisierul binar 
    int fd = open(path_reports, O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "SCORER: Nu pot deschide '%s'\n", path_reports);
        return 1;
    }

    //Array de scoruri per inspector 
    InspectorScore scoruri[MAX_INSPECTORS];
    int nr_inspectori = 0;

    // Citim rapoartele unul cate unul 
    Report r;
    while (read(fd, &r, sizeof(Report)) == (ssize_t)sizeof(Report)) {

      // Cautam daca inspectorul exista deja in array 
        int gasit = 0;
        for (int i = 0; i < nr_inspectori; i++) {
            if (strcmp(scoruri[i].name, r.inspector_name) == 0) {
	      // Inspector gasit - adunam severitatea 
                scoruri[i].workload += r.severity_level;
                gasit = 1;
                break;
            }
        }

        // Inspector nou - il adaugam in array 
        if (!gasit && nr_inspectori < MAX_INSPECTORS) {
            strncpy(scoruri[nr_inspectori].name, r.inspector_name, MAX_NAME - 1);
            scoruri[nr_inspectori].workload = r.severity_level;
            nr_inspectori++;
        }
    }
    close(fd);

    /* Scriem rezultatul la stdout
       city_hub va redirecta stdout-ul catre pipe cu dup2()
       deci acest printf va ajunge in pipe, nu pe ecran */
    printf("DISTRICT:%s\n", district);
    if (nr_inspectori == 0) {
        printf("  (nu exista rapoarte)\n");
    } else {
        for (int i = 0; i < nr_inspectori; i++) {
            printf("  Inspector %-20s workload=%d\n",
                   scoruri[i].name, scoruri[i].workload);
        }
    }
    // Marcaj de sfarsit - city_hub stie ca scorer-ul a terminat 
    printf("END_DISTRICT\n");

    return 0;
}

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif 

#include <err.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <string.h>
#include <my_global.h>
#include <mysql.h>

#include <nfc/nfc.h>
#include <nfc/nfc-types.h>
#include "../utils/nfc-utils.h"

#include "helpers.h"

#define MAX_DEVICES 5

static nfc_device *pnd = NULL;



int main(int argc,const char *argv[]) {
	const char* acLibnfcVer;
	size_t i;
	bool verbose = false;
	nfc_context *context;
	nfc_target nt;
	int arg=1;
	for(arg=1;arg<argc;arg++){
		if(strcmp(argv[arg],"-h")==0){
			print_usage(argv);
			exit(EXIT_SUCCESS);
		}
		else if(strcmp(argv[arg],"-v") == 0){
			verbose = true;
		}
		else if(strcmp(argv[arg],"-i") == 0){
			setenv("LIBNFC_INTRUSIVE_SCAN","yes",1);
		} else {
			ERR("%s not supported",argv[arg]);
			print_usage(argv);
			exit(EXIT_FAILURE);
		}
	}

	//Initialisation du nfc
	nfc_init(&context);
	if(!context) {
		ERR("Impossible d\'initialiser libnfc (malloc failed)\n");
		exit(EXIT_FAILURE);
	}

	acLibnfcVer = nfc_version();

	printf("%s utilise libfc %s\n",argv[0],acLibnfcVer);

	nfc_connstring connstrings[MAX_DEVICES];
	size_t szDevicesFound = nfc_list_devices(context,connstrings,MAX_DEVICES);
	if(szDevicesFound==0) {
		printf("Aucun NFC trouvé\n");
		nfc_exit(context);
		exit(EXIT_FAILURE);
	}

	printf("%d NFC trouvés:\n",(int)szDevicesFound);
	char *strinfo = NULL;
	MYSQL mysql;
			if(!mysql_init(&mysql)) exit(EXIT_FAILURE);

			if(!mysql_real_connect(&mysql,"127.0.0.1","root","test",NULL,3307,NULL,0)){
				printf("Database connection failed... ABORTING\n");
				exit(EXIT_FAILURE);
			}
	for(i=0;i<szDevicesFound;i++) {
		pnd = nfc_open(context,NULL); //NO NEED FOR CONNSTRING SINCE 1 DEV
		if(nfc_initiator_init(pnd) < 0) {
			nfc_perror(pnd,"nfc_initiator_init");
			exit(EXIT_FAILURE);
		}
		if(pnd) {
			printf("- %s: \n %s\n",nfc_device_get_name(pnd),
				nfc_device_get_connstring(pnd));

			const nfc_modulation nmMifare = {
				.nmt = NMT_ISO14443A,
				.nbr = NBR_106 //Baud rate 106
			};

			printf("Waiting for target...\n\n");
			while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,&nt) <= 0);
			printf("Target found\n");
			printf("NFC TAG (ISO14443A norm) :\n");
			printf("\tUID : ");
			print_hex(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);

			

			const char* hexstr = hexToStr(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);

			if(mysql_exec_sql(&mysql,"USE authaccess") != 0) {
				printf("COULD NOT USE DATABASE...ABORTING\n");
				exit(EXIT_FAILURE);
			}
			char statement[500];
			snprintf(statement,500,"SELECT * FROM authUsers WHERE uid = '%s'",hexstr);
			
			if(mysql_query(&mysql,statement) != 0){
				printf("NO SUCH UID...ABORTING\n");
				exit(EXIT_FAILURE);
			}
			MYSQL_RES *result = mysql_store_result(&mysql);
			if(!result) {
				printf("ERROR RETRIEVING DATA\n");
				mysql_close(&mysql);
				nfc_exit(context);
				exit(EXIT_FAILURE);
			}

			int num_f = mysql_num_fields(result);
			MYSQL_ROW row;
			row = mysql_fetch_row(result);

			if(atoi(row[5]) == 3) {
				printf("SUPER ADMIN %s %s\n",row[2],row[3]);
				printf("WAITING FOR SUPER ADMIN CARD REMOVAL...\n");
				while(nfc_initiator_target_is_present(pnd,NULL) == 0);
				printf("CARD REMOVED \n");
				printf("Waiting for target to insert into database...\n");
				while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,&nt) <= 0);
				printf("TARGET FOUND NFC ISO14443A\n");
				printf("UID : ");
				print_hex(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);
				char* uidToAdd = hexToStr(nt.nti.nai.abtUid,nt.nti.nai.szUidLen);
				printf("Please scan SUPER ADMIN target again to confirm\n");
				while(nfc_initiator_target_is_present(pnd,NULL) == 0);
				while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,&nt) <=0 );
				
				if(strcmp(lowercase((char*)hexstr),lowercase(hexToStr(nt.nti.nai.abtUid,nt.nti.nai.szUidLen))) == 0){
					printf("REQUEST CONFIRMED...ADDING\n");
					snprintf(statement,500,"INSERT INTO authUsers(uid,uname,ulastname,rank) VALUES ('%s','Unknown','Unknown',0)",uidToAdd);
					if(mysql_query(&mysql,statement) == 0) printf("UID %s ADDED TO AUTHORIZED USERS...EXITING\n",uidToAdd);
				}

			}

			if(verbose) {
				if(nfc_device_get_information_about(pnd,&strinfo) >= 0) {
					printf("%s",strinfo);
					nfc_free(strinfo);
				}
			}
			nfc_close(pnd);
			mysql_free_result(result);
		} else {
			printf("OPENING %s IMPOSSIBLE \n",connstrings[i]);
		}
		
	}
	mysql_close(&mysql);
	nfc_exit(context);
	exit(EXIT_SUCCESS);
}












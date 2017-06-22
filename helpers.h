#define RANK_COL 5
#define UID_COL 1
#define NAME_COL 2
#define LNAME_COL 3;

static const char* TableName = "authUsers";

static void print_usage(const char *argv[]) {
	printf("Utilisation: %s [OPTIONS]\n",argv[0]);
	printf("Options:\n");
	printf("\t-h\tPrint this help message.\n");
    printf("\t-v\tSet verbose display.\n");
    printf("\t-i\tAllow intrusive scan.\n");
}
 void
print_hex(const uint8_t *pbtData, const size_t szLen)
{
  size_t  szPos;

  for (szPos = 0; szPos < szLen; szPos++) {
    printf("%02x  ", pbtData[szPos]);
  }
  printf("\n");

}
int mysql_exec_sql(MYSQL *mysql,char *query) {
	if(strlen(query)>0)
		return mysql_real_query(mysql,query,strlen(query));
	return -1;
}

void init_db(MYSQL *mysql) {
	if(!mysql_init(mysql)) exit(EXIT_FAILURE);

	if(!mysql_real_connect(mysql,"127.0.0.1","root","test",NULL,3307,NULL,0)){
				printf("Database connection failed... ABORTING\n");
				exit(EXIT_FAILURE);
	}
	if(mysql_exec_sql(mysql,"USE authaccess") != 0) {
				printf("COULD NOT USE DATABASE...ABORTING\n");
				exit(EXIT_FAILURE);
	}
}


 char* lowercase(char* str) {
	int i=0;
	char* str1 = strdup(str);

	for(i=0;i<strlen(str);i++) {
		str1[i] = tolower(str1[i]);
	
	}
	return str1;


}

const char* hexToStr(uint8_t* hex,size_t len) {
	uint8_t* octet = (uint8_t*) hex;
	int i=0;
	char hexa[len];
	char hexstring[20] = "";

	while(i<len) {
		sprintf(hexa,"%02x",octet[i]);
		strcat(hexstring,hexa);
		//printf("%02x",octet[i++]);
		//fflush(stdout);
		i++;
	}
	char *str = malloc(sizeof(char)*len+1);

	hexstring[19] = '\0';
	str = strdup(hexstring);
	return str;

}

int handleUid(MYSQL *mysql,const char* uid) {
	int response=-1;
	char statement[500];
	snprintf(statement,500,"SELECT * FROM %s WHERE uid='%s'",TableName,uid);

	if(mysql_query(mysql,statement) != 0) {
		printf("NO SUCH UID...\n\n");
		return response;
	}

	MYSQL_RES *result = mysql_store_result(mysql);
	if(!result) {
		printf("ERROR RETRIEVING DATA\n");
		return -2;
	}
	int num_f = mysql_num_fields(result);
	MYSQL_ROW row;
	row = mysql_fetch_row(result);

	return atoi(row[RANK_COL]);
	mysql_free_result(result);


}

int addAuthUser(MYSQL *mysql,nfc_device *pnd,nfc_target *nt,
	const char *uid,const nfc_modulation nmMifare) {

	printf("SUPER ADMIN %s \n\n",uid);
	printf("WAITING FOR CARD REMOVAL...\n");
	while(nfc_initiator_target_is_present(pnd,NULL) == 0);
	printf("SUPER ADMIN CARD REMOVED\n");
	printf("WAITING FOR TARGET USER CARD...\n\n");
	while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,nt) <= 0);
	printf("TARGET DETECTED UID : ");
	print_hex(nt->nti.nai.abtUid,nt->nti.nai.szUidLen);
	const char *detuid = hexToStr(nt->nti.nai.abtUid,nt->nti.nai.szUidLen);
	if(strcmp(detuid,uid) == 0) return 1; //SUPER ADMIN ONLY ASKING FOR ACCESS
	printf("PLEASE SCAN SUPER ADMIN CARD FOR CONFIRMATION...\n");
	while(nfc_initiator_target_is_present(pnd,NULL) == 0);
	while(nfc_initiator_select_passive_target(pnd,nmMifare,NULL,0,nt) <= 0);

	if(strcmp(lowercase(uid),lowercase((const char*)hexToStr(nt->nti.nai.abtUid,nt->nti.nai.szUidLen))) == 0) {
		printf("ADDIND USER...\n");
		char statement[512];
		snprintf(statement,512,"REPLACE INTO %s (uid,uname,ulastname,rank) VALUES ('%s','Unknown','Unknown',0);",TableName,detuid);

		if(mysql_query(mysql,statement) != 0) {
			printf("ERROR ADDING USER\n");
			return -1;
		}
		printf("ADDED TO DATABASE UID : %s",detuid);

	printf("PLEASE REMOVE CARD\n");
	while(nfc_initiator_target_is_present(pnd,NULL) == 0);
	}
	else return -2;
	return 0;

}
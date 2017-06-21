#include <my_global.h>
#include <mysql.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int mysql_create_db(MYSQL *msql,char *query) {
	char cdb[255] = "CREATE DATABASE ";
	strcat(cdb,query);
	return mysql_real_query(msql,cdb,strlen(cdb));
}
int mysql_exec_sql(MYSQL *mysql,char *query) {
	if(strlen(query)>0)
		return mysql_real_query(mysql,query,strlen(query));
	return -1;
}


int main(int argc,char** argv) {
	MYSQL mysql;
	if(!mysql_init(&mysql)) exit(EXIT_FAILURE);
	
	//#if(!mysql_real_connect(&mysql,"127.0.01:3307","root","test",NULL,0,NULL,0))
	if(!mysql_real_connect(&mysql,"127.0.0.1","root","test",NULL,3307,NULL,0))
	{
		printf("Connection a la db impossible\n");
		exit(EXIT_FAILURE);

	}	
	char *dbname = "authaccess";
	
	if(mysql_create_db(&mysql,dbname) == 0) {
		printf("DATABASE CREATED\n");

	} else printf("FAILED TO CREATE DB ERROR :%s\n",mysql_error(&mysql));


	/*char *table = "CREATE TABLE authUsers( "
	"ID int NOT NULL AUTO_INCREMENT,"
	"uid varchar(20) NOT NULL,"
	"uname varchar(50),"
	"ulastname varchar(50),"
	"lastAccess TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
	"PRIMARY KEY(ID));";


	
	if(mysql_exec_sql(&mysql,table) == 0)
	{
		printf("TABLE CREATED IN DATABASE\n");
	} else {
		printf("FAILED TO CREATE TABLE ERROR :%s\n",mysql_error(&mysql));
	}*/
	mysql_exec_sql(&mysql,"USE authaccess");
	/*char * alter = "ALTER TABLE authUsers MODIFY COLUMN uid varchar(20) NOT NULL;";
	if(mysql_exec_sql(&mysql,alter) == 0)
	{
		printf("TABLE CREATED IN DATABASE\n");
	} else {
		printf("FAILED TO CREATE TABLE ERROR :%s\n",mysql_error(&mysql));
	}
	
	char * insert = "INSERT INTO authUsers (uid,uname,ulastname) "
	"VALUES ('0C30E399','Naif','Mehanna');";
	if(mysql_exec_sql(&mysql,insert) == 0)
	{
		printf("INSERT CREATED IN DATABASE\n");
	} else {
		printf("FAILED TO INSERTs :%s\n",mysql_error(&mysql));
	}*/
	mysql_query(&mysql,"SELECT * FROM authUsers");
	MYSQL_RES *result = mysql_store_result(&mysql);
	if(!result) {
		printf("ERROR RETRIEVING\n");

	}
	int num_f = mysql_num_fields(result);

	MYSQL_ROW row;
	MYSQL_FIELD *field;
	int i;
	while((row = mysql_fetch_row(result))) {
		
		for(i=0;i<num_f;i++) {
			printf("%s ",row[i] ? row[i] : "NULL");
		}
	}



	mysql_free_result(result);
	mysql_close(&mysql);
	exit(0);
}

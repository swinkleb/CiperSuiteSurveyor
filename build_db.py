import sqlite3, csv

def setup_db(website_file, cipher_suites_file):
	tables = ("cipher_suites", "websites", "offered_cipher_suites")
	conn = sqlite3.connect('survey.db')
	cursor = conn.cursor()

	#drop tables if they exist
	drop_tables(tables, cursor, conn)

	#create the tables
	create_db(cursor, conn)

	#populate the tables
	populate_db(website_file, cipher_suites_file, cursor, conn)

	#close the db
	conn.close()

	return

def create_db(cursor, conn):
	#create tables for storing the survey

	#create websites table
	cursor.execute('''CREATE TABLE cipher_suites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hex VARCHAR(8) NOT NULL, 
		name VARCHAR(255) NOT NULL,
		protocol VARCHAR(3),
		kx VARCHAR(255),
		au VARCHAR(255),
		enc VARCHAR(255),
		bits INTEGER,
		mac VARCHAR(255), 
		strength VARCHAR(10)
		)''')

	#create ciphersuites table
	cursor.execute('''CREATE TABLE websites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(255) NOT NULL 
		)''')

	#create offered ciphersuites table
	cursor.execute('''CREATE TABLE offered_cipher_suites (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		website_id INTEGER NOT NULL,
		cipher_id INTEGER NOT NULL,
		tls_id INTEGER NOT NULL,
		FOREIGN KEY(website_id) REFERENCES websites(id),
		FOREIGN KEY(cipher_id) REFERENCES cipher_suites(id)
		)''')

	#save the changes
	conn.commit()

	return

def drop_tables(table_list, cursor, conn):
	for table in table_list:
		#this is bad but oh, well -- should use ?
		cursor.execute('DROP TABLE IF EXISTS %s' % table)

	conn.commit()

	return

def populate_db(website_file, cipher_suites_file, cursor, conn):
	
	websites = csv.reader(open(website_file))
	conn.executemany("INSERT INTO websites(id, name) values (?,?)", websites)
	conn.commit()

	suites = csv.reader(open(cipher_suites_file, 'rU'))
	conn.executemany("INSERT INTO cipher_suites(hex, name, protocol, kx, au, enc, bits, mac, strength) values (?,?,?,?,?,?,?,?,?)", suites)
	conn.commit()

	return

def main():
	setup_db("./top-1m.csv", "./ciphersuites.csv")
	return

if __name__ == '__main__':
	main()
CREATE TABLE cipher_suites (
	id INTEGER PRIMARY KEY,
	name VARCHAR(255) NOT NULL,
	is_secure BOOLEAN
);

CREATE TABLE websites (
	id INTEGER PRIMARY KEY,
	name VARCHAR(255) NOT NULL 
);

CREATE TABLE offered_cipher_suites (
	id INTEGER PRIMARY KEY,
	website_id INTEGER NOT NULL,
	cipher_id INTEGER NOT NULL,
	FOREIGN KEY(website_id) REFERENCES websites(id),
	FOREIGN KEY(cipher_id) REFERENCES cipher_suites(id)
);
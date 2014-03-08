import socket, logging, getopt, sys, binascii, sqlite3

client_hello = (
'\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20', #TLS v1.3
'\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20', #TLS v1.2
'\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20', #TLS v1.1
'\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20', #TLS v1.0
'\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20', #SSL v3.0
)

CHALLENGE = '\x00' * 32
SERVER_HELLO = '\x16'
SERVER_ALERT = '\x15'

ACCEPTED=0
REJECTED=1
TIMEOUT=2
ERROR=3

def is_cipher_accepted(cipher, host, port, logger, index):
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	soc.settimeout(4)

	handshake = client_hello[index]
	
	#create streaming socket, attempt to connect to specified host on given port
	try: 
		soc.connect((host, port))
	except socket.timeout:
		logger.error('Connection timed out on host: %s using port: %s' % (host, port))
		soc.close()
		return TIMEOUT
	except socket.error, (value, message):
		logger.error('Failed to connect to host: %s using port: %s' % (host, port))
		soc.close()
		return ERROR

	#if (logger.isEnabledFor(logging.DEBUG)):
	#	logger.debug('Sending packet: \n \thandshake: %s\n \tcipher: %s \n' % (handshake, cipher))

	#send client hello packet
	soc.send(handshake+cipher+CHALLENGE)

	#recieve response from server
	try: 
		response = soc.recv(1)
	except socket.timeout:
		soc.close()
		return TIMEOUT

	isAccepted = REJECTED

	# if response is type server hello the cipher suite was accepted
	if response == SERVER_HELLO:
		isAccepted = ACCEPTED

	#if (logger.isEnabledFor(logging.DEBUG)):
	#	logger.debug('Cipher suite was accepted: %s' % isAccepted) 

	soc.close()

	return isAccepted

def main():
	#set up log 
	#loglevel = getopt(sys.argv[1:], "log:")
	#print loglevel
	#logging_level = getattr(logging, loglevel.upper(), None)
	#if not isinstance(logging_level, int):
	#	print "please specify loggin level with --log=<LEVEL>"
	#	sys.exit()

	#defines what tls version to use
	tls_index = 0;

	logging.basicConfig(filename='debug.log',level=logging.DEBUG)
	logger = logging.getLogger()

	conn = sqlite3.connect('survey.db')
	cursor = conn.cursor()
	
	cipher_ids = cursor.execute('SELECT * FROM cipher_suites').fetchall()
	websites = cursor.execute('SELECT * FROM websites ORDER BY id').fetchall()

	#do work
	for website in websites:
		print 'CHECKING: %s' % website[1]
		timeout_counter = 0
		for cipher in cipher_ids:
			#print cipher[1]
			isAccepted = is_cipher_accepted(binascii.unhexlify(cipher[1]), website[1], 443, logger, tls_index)

			if isAccepted == ACCEPTED:
				cursor.execute("INSERT INTO offered_cipher_suites(website_id, cipher_id, tls_id) values (?,?,?)",  (website[0], cipher[0], tls_index))
			elif isAccepted == TIMEOUT:
				timeout_counter += 1
				if timeout_counter > 10:
					logger.info('No response from website (timeout): %s, skipping' % website[1])
					break
			elif isAccepted == ERROR:
				logger.info('No response from website (error): %s, skipping' % website[1])
				break

		conn.commit()
	
	return

if __name__ == '__main__':
	main()
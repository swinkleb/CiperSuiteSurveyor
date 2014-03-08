import socket, logging, getopt, sys, binascii

client_hello = {
"TLSv1.3": '\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20',
"TLSv1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
"TLSv1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
"TLSv1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
"SSLv3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20',
#"SSLv2.0": '\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'
}

challenge = '\x00' * 32
SERVER_HELLO = '\x16'
SERVER_ALERT = '\x15'

def is_cipher_accepted(cipher, host, port, logger):
	soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	soc.settimeout(4)
	handshake = client_hello["TLSv1.3"]
	
	#create streaming socket, attempt to connect to specified host on given port
	try: 
		soc.connect((host, port))
	except socket.error, (value, message):
		logger.error('Failed to connect to host: %s using port: %s' % (host, port))
		soc.close()
		return False

	if (logger.isEnabledFor(logging.DEBUG)):
		logger.debug('Sending packet: \n \thandshake: %s\n \tcipher: %s \n' % (handshake, cipher))

	#send client hello packet
	soc.send(handshake+cipher+challenge)

	#recieve response from server
	try: 
		response = soc.recv(1)
	except socket.timeout:
		soc.close()
		return False

	# if response is type server hello the cipher suite was accepted
	isAccepted = response == SERVER_HELLO
	if (logger.isEnabledFor(logging.DEBUG)):
		logger.debug('Cipher suite was accepted: %s' % isAccepted) 

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

	logging.basicConfig(filename='debug.log',level=logging.DEBUG)
	logger = logging.getLogger()

	#do work
	print "%s" % is_cipher_accepted(binascii.unhexlify('FFC02F'), "www.google.com", 443, logger)
	return

if __name__ == '__main__':
	main()
import requests
import json
import time

path = "https://api.ssllabs.com/api/v2/analyze"

c = open('accepted_ciphers.txt', 'r')
accepted_ciphers = c.readlines()
ios_ciphers = []
for i in accepted_ciphers:
	foo = i.strip('\n')
	ios_ciphers.append(foo)

f = open('endpoints.txt', 'r')
endpoints = f.readlines()

def testBit(int_type, offset):
	mask = 1 << offset
	return(int_type & mask)


for ep in endpoints:
	host = ep.rstrip()
	print host
	payload = {'host': host, 'publish': 'off', 'startNew': 'off', 'fromCache': 'on', 'ignoreMismatch': 'on', 'all': 'done'}
	try:
		r = requests.get("https://api.ssllabs.com/api/v2/analyze", params=payload)
	except requests.exceptions.RequestException as e:
		with open("error.txt", "a") as errfile:
			errfile.write(str(e))
		print str(e) + '\n'
	result = r.json()
	print result
	if ('errors' in result) and ('Concurrent assessment limit reached' in result['errors'][0]['message']):
		time.sleep( 15 )
	if (('endpoints' in result) and (not 'errors' in result)):
		try:
			print '====== 001 ======'
			if (('details' in result['endpoints'][0]) and (result['endpoints'][0]['statusMessage'] != 'No secure protocols supported') and (result['endpoints'][0]['statusMessage'] != 'Unable to connect to server')):
				try:
					print '====== 002 ======'
					if result['endpoints'][0]['details']['suites']['list']:
						unsupported_cipher = '"'
						configured_ciphers = [] 
						for suite in result['endpoints'][0]['details']['suites']['list']:
							configured_ciphers.append(str(suite['name']))
							#print accepted_ciphers
						for cipher in ios_ciphers:
							if (cipher not in configured_ciphers):
								unsupported_cipher = unsupported_cipher + cipher + ','
						unsupported_cipher = unsupported_cipher + '"'
					else:
						unsupported_cipher = 'Error enumerating configured ciphers'
					print '====== 003 ======'
					poodlevar = result['endpoints'][0]['details']['poodleTls']
					if poodlevar == 2:
						poodleTls = 'Vulnerable to Poodle'
					elif poodlevar == 1:
						poodleTls = 'Not Vulnerable to Poodle'
					else:
						poodleTls = 'Poodle Test Failed'
					print '====== 004 ======'
					SSLV2 = SSLV3 = TLS10 = TLS11 = TLS12 = "Error"
					for protocol in result['endpoints'][0]['details']['protocols']:
						if "SSL" in protocol['name'] and protocol['version']=="2.0":
							SSLV2 = 'SSL V2 enabled'
						else:
							SSLV2 = 'SSL V2 disabled'
						if "SSL" in protocol['name'] and protocol['version']=="3.0":
							SSLV3 = 'SSL V3 enabled'
						else:
							SSLV3 = 'SSL V3 disabled'
						if "TLS" in protocol['name'] and protocol['version']=="1.2":
							TLS12 = 'TLS 1.2 enabled'
						else:
							TLS12 = 'TLS 1.2 disabled'
						if "TLS" in protocol['name'] and protocol['version']=="1.1":
							TLS11 = 'TLS 1.1 enabled'
						else:
							TLS11 = 'TLS 1.1 disabled'
						if "TLS" in protocol['name'] and protocol['version']=="1.0":
							TLS10 = 'TLS 1.0 enabled'
						else:
							TLS10 = 'TLS 1.0 disabled'
					print '====== 005 ======'
					certmsg = int(result['endpoints'][0]['details']['cert']['issues'])
					ntbef = testBit(certmsg, 1)
					ntaf = testBit(certmsg, 2)
					if ntbef != 0 or ntaf != 0:
						certexp = "Expired"
					else:
						certexp = "Not Expired"
					print '====== 006 ======'
					certmsg = int(result['endpoints'][0]['details']['cert']['issues'])
					chainp = testBit(certmsg, 6)
					if chainp != 0:
						selfcert ="Self Signed Cert"
					print '====== 007 ======'
					certmsg = int(result['endpoints'][0]['details']['cert']['issues'])
					chainp = testBit(certmsg, 3)
					if chainp != 0:
						wrongdomain = "Domain mismatch"
					else:
						wrongdomain = "Domain matched"
					revoc_status = int(result['endpoints'][0]['details']['cert']['revocationInfo'])
					if (revoc_status == 1):
						revoc = "Revoked"
					elif (revoc_status == 2):
						revoc = "Not Revoked"
					elif (revoc_status == 4):
						revoc = "No revocation info"
					elif (revoc_status == 0):
						revoc = "Revocation not checked"
					elif ((revoc_status == 3) or (revoc_status == 5)):
						revoc = "Error during revocation check"
					print '====== 008 ======'
					ocsp_revoc_status = int(result['endpoints'][0]['details']['cert']['ocspRevocationStatus'])
					if (ocsp_revoc_status == 1):
						ocsp_revoc = "Revoked"
					elif (ocsp_revoc_status == 2):
						ocsp_revoc = "Not Revoked"
					elif (ocsp_revoc_status == 4):
						ocsp_revoc = "No revocation info"
					elif (ocsp_revoc_status == 0):
						ocsp_revoc = "Revocation not checked"
					elif ((ocsp_revoc_status == 3) or (ocsp_revoc_status == 5)):
						ocsp_revoc = "Error during ocsp revocation check"
					cert_chain = '"'
					for i in result['endpoints'][0]['details']['chain']['certs']:
						cert_chain = cert_chain + i['issuerLabel'] + ' ' + i['keyAlg'] + ' ' +  str(i['keySize']) + ' ' + i['sigAlg'] + ', '
					cert_chain = cert_chain + '"'

					host = result['host']
					common_name = str(result['endpoints'][0]['details']['cert']['commonNames'][0])
					key_algo = result['endpoints'][0]['details']['key']['alg']
					key_strength = int(result['endpoints'][0]['details']['key']['size'])
					sign_algo = result['endpoints'][0]['details']['cert']['sigAlg']
					row =  host + ',' + common_name + ',' + key_algo + ',' + str(key_strength) + ',' + sign_algo + ',' + cert_chain + ',' + revoc + ',' + ocsp_revoc + ',' + poodleTls + ',' + unsupported_cipher + ',' + SSLV2 + ',' + SSLV3 + ',' + TLS10 + ',' + TLS11 + ',' + TLS12 + '\n'
					print '\n'
					print '====== 009 ======'
					with open("output_again.txt", "a") as myfile:
						myfile.write(row)
					myfile.close()
				except Exception,e:
					raise
					print str(result['endpoints'][0]['statusMessage']) + '\n'
					print str(e)
			else:
				print result
				error = host + ' scan not ready on ssllabs ' + str(result['endpoints'][0]['statusMessage']) + '\n'
				
				print error
				with open('failed.txt', 'a') as failedfile:
					failedfile.write(error)
				failedfile.close()
		except Exception,e:
			raise
			print str(result['endpoints'][0]['statusMessage']) + '\n'
			print result
			print str(e)
	else:
		try:
			if (('status' in result) and (str(result['status']) == 'DNS')):
				err = host + 'failed due to DNS issue' + '\n'
			elif ('errors' in result):
				err = host + ' ' +str(result['errors']) + '\n'
				print err
				with open('failed.txt', 'a') as failedfile:
					failedfile.write(err)
				failedfile.close()
		except Exception,e:
			raise	

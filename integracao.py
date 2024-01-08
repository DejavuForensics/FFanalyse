import FFanalyse

domain = 'google.com';
verbose = False;
ip = []
ip.append('195.113.214.245');
ip.append('195.113.214.222');
ip.append('195.113.214.236');

ff = FFanalyse.ffanalyse()
ff.main(domain,verbose,ip)
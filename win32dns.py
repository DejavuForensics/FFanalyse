from berserker_resolver import Resolver


def RegistryResolve(domain):
	nameservers=[]
	domains = [domain]

	resolver = Resolver()
	result = resolver.resolve(domains)
	for x in result[domain]:
		nameservers.append(x.to_text())
	return nameservers

if __name__=="__main__":
    print("Name servers:",RegistryResolve(domain))
	
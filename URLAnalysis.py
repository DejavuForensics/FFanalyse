#!/usr/bin/python
import sys
import pickle
import argparse
import os
import math

"""
Performs Domain name analysis using different statistical techniques. Aims to detect whether a domain is a DGA.
Author: Etienne Stalmans (etienne@sensepost.com)
Version: 1.4 (2013)
"""

BIGRAM = 0
UNIGRAM = 1

class urlanalyse:
    def main(self,safe_in,malicious_in):    
        """
        Initialize the frequency tables. Uses pretrained input obtained from TrainURLAnalysis.py
        @param safe_in the trained frequency set for "clean" domains or known non-DGA values (english dictionary ect)
        @param malicious_in the trained frequency set for "DGA" domains (confiker,kraken,torpig,ect)
        """
        s_in = open(safe_in,'rb')
        m_in = open(malicious_in,'rb')

        self.s_frequencies = pickle.load(s_in)
        self.s_frequencies_bi = pickle.load(s_in)
        self.m_frequencies = pickle.load(m_in)
        self.m_frequencies_bi = pickle.load(m_in)

        s_in.close()
        m_in.close()

    def checkDomain(self,domain):
        if os.path.isfile(domain):
            domains = []
            d_in = open(domain,'r')
            for dom in d_in:
                domains.append(dom)
            d_in.close()
        else:
            domains = [domain]

        for d in domains:
            dom =  d.lower().rstrip('\n').split('.')[0] #get lowest level domain and tolower - should probably do case sensitivity?
            N = len(d)
            
            print ("\033[93mDomain: %s\033[0m"%d.strip())
            
            [a,b,c] = self.entropy_test(dom,UNIGRAM)
            print ("Entropy analysis (UNIGRAM): %s, entropy: %f, entropy_m: %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [a,b,c] = self.entropy_test(dom,BIGRAM)
            print ("Entropy analysis (BIGRAM): %s, entropy: %f, entropy_m: %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [a,b,c] = self.probability_test(dom,UNIGRAM)
            print ("Probability analysis (UNIGRAM): %s, countm %f, count %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [a,b,c] = self.probability_test(dom,BIGRAM)
            print ("Probability analysis (BIGRAM): %s, countm %f, count %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [a,b,c] = self.totalvariation_test(dom,UNIGRAM)
            print ("Total Variation analysis (UNIGRAM): %s, pq %f,boundary %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [a,b,c] = self.totalvariation_test(dom,BIGRAM)
            print ("Total Variation analysis (BIGRAM): %s, pq %f,boundary %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [bias_u,ba,ca] = self.naivebayes_test(dom,UNIGRAM) #so that we can use Naive Bayes as the bias for Standard Bayesian
            [bias_b,bb,cb] = self.naivebayes_test(dom,BIGRAM)
            print ("Naive-Bayesian analysis (UNIGRAM): %s, su %f, pM %f"%("\033[91mDGA\033[0m" if bias_u == 1 else "\033[92mBenign\033[0m",ba,ca))
            print ("Naive-Bayesian analysis (BIGRAM): %s, su %f, pM %f"%("\033[91mDGA\033[0m" if bias_b == 1 else "\033[92mBenign\033[0m",bb,cb))
            [a,b,c] = self.bayesian_test(dom,bias_u,UNIGRAM)
            print ("Bayesian analysis (UNIGRAM): %s pq %f, boundary %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))
            [a,b,c] = self.bayesian_test(dom,bias_b,BIGRAM)
            print ("Bayesian analysis (BIGRAM): %s pq  %f, boundary %f"%("\033[91mDGA\033[0m" if a == 1 else "\033[92mBenign\033[0m",b,c))

    def entropy_test(self,domain,test_type=UNIGRAM):
        entropy = 0
        entropy_m = 0
        
        if test_type == UNIGRAM:
            for c in domain:
                if (c in self.s_frequencies and c in self.m_frequencies) and (self.s_frequencies[c]!=0.0 and self.m_frequencies[c]!=0.0):
                    entropy += self.s_frequencies[c]*math.log(self.s_frequencies[c],2)
                    entropy_m += self.m_frequencies[c]*math.log(self.m_frequencies[c],2)
        else:
            
            for i in range(0,len(domain)-1):
                c = domain[i:i+2]
                if (c in self.s_frequencies_bi and c in self.m_frequencies_bi) and (self.s_frequencies_bi[c]!=0.0 and self.m_frequencies_bi[c]!=0.0):
                    entropy += self.s_frequencies_bi[c]*math.log(self.s_frequencies_bi[c],2)
                    entropy_m += self.m_frequencies_bi[c]*math.log(self.m_frequencies_bi[c],2)
        
        if entropy < entropy_m:
            return [0,entropy,entropy_m]
        else:
            return [1,entropy,entropy_m]

    def probability_test(self,domain,test_type=UNIGRAM):
        n = len(domain)
        countm = 1.0
        count = 1.0
        
        if test_type == UNIGRAM:
            for c in domain:
                if c in self.s_frequencies:
                    count *= self.s_frequencies[c]
                    countm *= self.m_frequencies[c]
        else:
            for i in range(1,len(domain)):
                c = domain[i-1:i+1]
                if c in self.s_frequencies_bi:
                    count *= self.s_frequencies_bi[c]
                    countm *= self.m_frequencies_bi[c]
        
        if countm > count:
            return [1,countm, count]
        else:
            return [0,countm, count]
    
    def naivebayes_test(self,domain,test_type):
        N = len(domain)
        su = 0.0
        
        if test_type == UNIGRAM:         
            nbayes_bound=0.005 #decision boundary, generated from testing
            for c in domain:
                 if c in self.s_frequencies:
                     if self.s_frequencies[c]!=0.0 and self.m_frequencies[c]!=0.0:
                         su += math.log(self.m_frequencies[c]/self.s_frequencies[c])
        else:
            nbayes_bound=0.5       
            for i in range(1,len(domain)):
                 c = domain[i-1:i+1]
                 if c in self.s_frequencies_bi:
                     if self.s_frequencies_bi[c]!=0.0 and self.m_frequencies_bi[c]!=0.0:
                         su += math.log(self.m_frequencies_bi[c]/self.s_frequencies_bi[c])
                     
        pM = nbayes_bound
        if su >= pM:      
               return [1,su,pM]            
        else:      
               return [0,su,pM]

    def bayesian_test(self,domain,bias,test_type=UNIGRAM):
        H1 = bias
        H2 = 1-bias
        if H1 == 0 or H2 == 0:
            H1 = 0.5
            H2 = 0.5
        x = 0.0
        pt = 1
        pb = 1
        PT = 1
        PB = 1
        bayesBound = 0.4

        if test_type == UNIGRAM:
            for i in domain:
                if i in self.m_frequencies and i in self.s_frequencies:
                    pt *= self.m_frequencies[i]/(self.m_frequencies[i]+self.s_frequencies[i])
                    pb *= (1-self.m_frequencies[i]/(self.m_frequencies[i]+self.s_frequencies[i]))
                    PT *= self.m_frequencies[i]*H1/(self.m_frequencies[i]*H1+self.s_frequencies[i]*H2)
                    PB *= (1-self.m_frequencies[i]*H1/(self.m_frequencies[i]*H1+self.s_frequencies[i]*H2))
        else:
            for l in range(0,len(domain)-1):
                i = domain[l:l+2]
                if len(i) >=0 :
                    if i in self.s_frequencies_bi and self.s_frequencies_bi[i] != 0.0 and self.m_frequencies_bi[i] != 0.0:
                        pt *= self.m_frequencies_bi[i]/(self.m_frequencies_bi[i]+self.s_frequencies_bi[i])
                        pb *= (1- self.m_frequencies_bi[i]/(self.m_frequencies_bi[i]+self.s_frequencies_bi[i]))
                        PT *= self.m_frequencies_bi[i]*H1/(self.m_frequencies_bi[i]*H1+self.s_frequencies_bi[i]*H2)
                        PB *= (1-self.m_frequencies_bi[i]*H1/(self.m_frequencies_bi[i]*H1+self.s_frequencies_bi[i]*H2))
                
        ptot = pt/(pt+pb)
        P = PT/(PT+PB)

        if P >= bayesBound:
            return [1,P,bayesBound]
        else:
            return [0,P,bayesBound]

    def totalvariation_test(self,domain,test_type):
        n = len(domain)
        pq = 0.0
        su = 0.0
 
        if test_type == UNIGRAM:
            boundary = 0.05
            for c in domain:
                if c in self.s_frequencies:
                    tmp = self.s_frequencies[c]-self.m_frequencies[c]
                    su += tmp
        else:
            boundary = 0.004
            for i in range(1,len(domain)):
                c = domain[i-1:i+1]
                if c in self.s_frequencies_bi:
                    tmp = self.s_frequencies_bi[c]-self.m_frequencies_bi[c]
                    su += tmp
        
        pq = 0.5*su

        if pq < boundary:
            return [1,pq,boundary]        
        else:
            return [0,pq,boundary]

class displayHelp(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        print ("Please supply trained data for both benign and malicious domains.")
        print ("To train, please see TrainURLAnalysis.py")
        print ("Example: python URLAnalyis.py trained_b.dgt trained_m.dgt\n\n")

if __name__ == "__main__":
    

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-b',dest='safe',action='store',required=True,
        help="Trained benign (safe) data")
    parser.add_argument('-m',dest='malicious',action='store',required=True,
        help="Trained malicious (Known DGA) data")
    parser.add_argument('-d',dest='domain',action='store',required=True,
        help="The domain to check. Supply a file with one domain per line to check multiple domains.")
    parser.add_argument('-v', dest='verbose', action='store_true',default=False,
        help="Verbose output")
    parser.add_argument('-h','--help',nargs=0,action=displayHelp)

    arg = parser.parse_args()
    urla = urlanalyse()
    urla.main(arg.__dict__['safe'],arg.__dict__['malicious'])
    urla.checkDomain(arg.__dict__['domain'])



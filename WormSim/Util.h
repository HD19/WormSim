#ifndef _UTIL_H
#define _UTIL_H

#include "Common.h"
#include <random>

typedef std::mt19937 MyRNG;

using namespace std;

enum class IPType { Range, Single };

class IPAddress
{
public:
	IPAddress();
	IPAddress(string strIP);
	IPAddress(uint intIP);
	IPAddress& operator=(const IPAddress& rhs);
	uint operator-(const IPAddress& rhs);
	uint getIntRep();
	string& getStrRep();
	bool  setMakBits(uint toSet);
	static uint intRep(string toConvert);
	static string strRep(uint toConvert);
	static bool   validateIP(string toValidate);
	static bool   isCIDR(string toCheck);
	static IPAddress generateRandomIP(MyRNG* rng);
	static IPAddress generateRandomBlock(MyRNG* rng, uint maskBits);
	bool   isInRange(const IPAddress& toCheck);
	uint   getNetworkSize();
	IPType getType();
	//IPVect* getRangeIPs();
private:
	//If someone wants our range of IP's, it'll be calculated and handed out, someone else should manage it
	void   updateReps();
	string strAddress; //Cache one or the other
	uint   intAddress;
	uint   netmask;	   //Netmask for CIDR address
	uint   addrCount; //If it's a range, this will give the size of the address space.
	IPType addrType;
	IPAddress* startAddr; //If this is a range, this represents the starting single address.
	IPAddress* endAddr; //If this is a range, will represent the last address.
};

typedef vector<IPAddress> IPVect;
typedef vector<IPAddress>::iterator IPVectItr;

#endif
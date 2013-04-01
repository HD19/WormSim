#ifndef _UTIL_H
#define _UTIL_H

#include "Common.h"

using namespace std;

enum class IPType { Range, Single };

typedef vector<IPAddress> IPVect;
typedef vector<IPAddress>::iterator IPVectItr;

class IPAddress
{
public:
	IPAddress();
	IPAddress(string strIP);
	IPAddress(uint intIP);
	uint getIntRep();
	string& getStrRep();
	static uint intRep(string toConvert);
	static string strRep(uint toConvert);
	IPType getType();
	IPVect* getRangeIPs;
private:
	//If someone wants our range of IP's, it'll be calculated and handed out, someone else should manage it
	void   updateReps();
	bool   validateIP();
	string strAddress; //Cache one or the other
	uint   intAddress;
	IPType addrType;
	uint   addrCount; //If it's a range, this will give the size of the address space.
	IPAddress* startAddr; //If this is a range, this represents the starting single address.
	IPAddress* endAddr; //If this is a range, will represent the last address.
};

#endif
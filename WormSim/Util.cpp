#include "Util.h"

class IPAddress
{
public:
	IPAddress();
	IPAddress(string strIP);
	IPAddress(uint intIP);
	uint operator-(const IPAddress& rhs);
	uint getIntRep();
	string& getStrRep();
	static uint intRep(string toConvert);
	static string strRep(uint toConvert);
	static bool   validateIP(string toValidate);
	static bool   isCIDR(string toCheck);
	uint   getNetworkSize();
	IPType getType();
	IPVect* getRangeIPs;
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

IPAddress::IPAddress()
{
	strAddress = "";
	intAddress = 0;
	addrType = IPType::Single;	//This will be updated on converting the type, or switching the IP
	addrCount = 0;
	startAddr = NULL;
	endAddr = NULL;
}

IPAddress::IPAddress(string strIP): strAddress(strIP)
{
	if(!validateIP(strAddress))
	{
		throw new exception("Invalid IP string given for IPAddress construction");
	}
	if(isCIDR(strAddress))
	{
		//we got a CIDR address. Calculate the ranges and stuff
		stringstream ss(strAddress);
		string baseIP;
		string tmpIP;
		uint iBaseIP;
		uint iFirstIP;
		uint iLastIP;
		unsigned char ext;
		getline(ss, baseIP, '/');
		getline(ss, tmpIP); //should be a number < 32

		ext = (unsigned char)(atoi(tmpIP.c_str())& 0xFF);
		if(ext > 32)
		{
			throw new exception("CIDR bits set too high!");
			return;
		}

		//ext is the number of bits set
		//get the base IP
		iBaseIP = intRep(baseIP);
		int mask = (INT32_MIN >> ext); //arithmetic shift right, should be shifting in ones from the left
		iFirstIP = (iBaseIP & mask);    //Get the first address
		int invMask = !(mask);			// make the other bits 0
		iLastIP = iFirstIP + invMask;
		startAddr = new IPAddress(iFirstIP);
		endAddr = new IPAddress(iLastIP);
		netmask = mask;
		addrCount = (endAddr - startAddr) + 1;
	}
	updateReps();
}

IPAddress::IPAddress(uint intIP): intAddress(intIP)
{
	//This can't ever be a range, nor can it be invalid on a 32-bit system
	//But for whatever's sake, we'll check to see if the uint is > 2^32
	if(intIP > INT32_MAX)
	{
		throw new exception("Invalid integer given for IPAddress construction, only supporting IPV4");
	}

	this->addrType = IPType::Single;
	updateReps();
}

uint IPAddress::getIntRep()
{
	//returns integer representation of IPAddr object
	return this->intAddress;
}

string& IPAddress::getStrRep()
{
	//returns string representation of IPAddr object
	return this->strAddress;
}

uint IPAddress::intRep(string toConvert)
{
	//Convert a string representation address to an integer
	uint toRet = 0;
	//assume we get an ip like so: "x.x.x.x"
	//Lets get a string stream going to tokenize
	string quads[4];
	istringstream iss(toConvert);
	for(int i = 0; i < 4; i++)
	{
		try
		{
			getline(iss, quads[i], '.');
			uint tmpi = atoi(quads[i].c_str);
			if( tmpi > 0xFF)
			{
				throw new exception("doted quad segment greater than 255");
			}
		}
		catch (exception& ex)
		{
			cout << "Failed to get integer representation of " << toConvert << endl << ex.what() << endl;
			return 0;
		}
	}

	for(int i = 3; i >= 0; i--)
	{
		//Generate the IP
		unsigned char tmp = (char)atoi(quads[i].c_str()) & 0xFF;
		toRet |= (tmp << i*8);
	}
	return toRet;
}

string IPAddress::strRep(uint toConvert)
{
	stringstream ss;
	unsigned char bytes[4];

	bytes[0] = toConvert & 0xFF;
	bytes[1] = (toConvert >> 8) & 0xFF;
	bytes[2] = (toConvert >> 16) & 0xFF;
	bytes[3] = (toConvert >> 24) & 0xFF;

	for(int i = 3; i >= 0; i--)
	{
		ss << bytes[i];
		if(!i)
		{
			ss << '.';
		}
	}

	return ss.str();
}

void IPAddress::updateReps()
{
	//If the string is set, adjust the integer accordingly
	//If the integer is set, adjust the string accordingly

	//We don't want to update ranges.
	if(this->strAddress != "" && this->addrType != IPType::Range)
	{
		//assume string was most recently updated.
		this->intAddress = intRep(strAddress);
	}
	else if (this->addrType == IPType::Single)
	{
		//this says we have the intAddress and we need to fix up the string address. Should be single
		this->strAddress = strRep(intAddress);
	}
}

uint IPAddress::operator-(const IPAddress& rhs)
{
	return max(intAddress, rhs.intAddress) - min(intAddress, rhs.intAddress);
}

bool IPAddress::validateIP(string toValidate)
{
	//lets do a try catch on parsing.
	string ipStr("^([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
	string cidrStr(ipStr.substr(0, ipStr.length()-2)); //We want the string minus the ending character
	
	cidrStr += "/[012]?\\d|3[012]$";

	regex ipReg(ipStr);
	regex cidrReg(cidrStr);
	if(regex_match(toValidate, ipReg))
		return true;
	if(regex_match(toValidate, cidrReg))
		return true;

	return false;
}

bool IPAddress::isCIDR(string toCheck)
{
	//CIDR adddresses look like so 
	//192.168.0.1/24
	regex cidrReg("^([01]?\\d\\d?|2[0-4]\\d|25[0-4])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-4])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-4])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-4])/[012]?\\d|3[012]$");

	if(regex_match(toCheck, cidrReg))
		return true;

	return false;
}

uint IPAddress::getNetworkSize()
{
	if(addrType == IPType::Range)
	{
		return this->addrCount;
	}
	return 1;
}

IPType IPAddress::getType()
{
	return addrType;
}
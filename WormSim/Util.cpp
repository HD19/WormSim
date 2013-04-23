#include "Util.h"

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
	//Starting address should ONLY be defined for ranges!
	if(isCIDR(strAddress))
	{
		//we got a CIDR address. Calculate the ranges and stuff
		stringstream ss(strAddress);
		string baseIP;
		string tmpIP;
		unsigned char ext;
		getline(ss, baseIP, '/');
		getline(ss, tmpIP); //should be a number < 32


		ext = (unsigned char)(atoi(tmpIP.c_str())& 0xFF);
		if(ext > 32)
		{
			throw new exception("CIDR bits set too high!");
			return;
		}
		//WARNING: There might be an error here, this can fail.
		if(!this->setMakBits(ext))
		{
			throw new exception("Invalid bits given for mask in CIDR address IPAddr Construction!");
			return;
			
		}
	}
	updateReps();
	return;
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



IPAddress& IPAddress::operator=(const IPAddress& rhs)
{
	this->strAddress = rhs.strAddress;
	this->intAddress = rhs.intAddress;
	this->netmask = rhs.netmask;
	this->addrCount = rhs.addrCount;
	this->addrType = rhs.addrType;
	if(this->addrType == IPType::Range)
	{
		this->startAddr = new IPAddress(rhs.startAddr->intAddress);
		this->endAddr = new IPAddress(rhs.endAddr->intAddress);
	}
	else
	{
		this->startAddr = NULL;
		this->endAddr = NULL;
	}

	return *this;
}

IPAddress IPAddress::generateRandomIP(MyRNG* rng)
{
	//rng should be an initialized random number generator
	std::uniform_int_distribution<uint32_t> octalDist(1, 255); //range is 1 - 255!

	uint resIntIP = 0;

	for(uint i = 0; i < 4; i++)
	{
		uint piece = octalDist(*rng);
		//resIntIP |= ( octalDist(rng) << (24 - (8 * i)));
	}
	return IPAddress(resIntIP);
}

IPAddress IPAddress::generateRandomBlock(MyRNG* rng, uint maskBits)
{
	//get base address
	IPAddress base = generateRandomIP(rng);

	//make it a block
	base.setMakBits(maskBits);
	return base;
}

bool IPAddress::setMakBits(uint toSet)
{
	//we don't want to be able to set addresses to singles
	if( (32 - toSet) < 1 || (32 - toSet) > 32 )
	{
		return false;
	}
	//turn the IP into a range by setting the mask bits and stuff.
	addrType = IPType::Range;
	//ext is the number of bits set
	//get the base IP
	uint iBaseIP = this->intAddress;
	int mask = (INT32_MIN >> toSet); //arithmetic shift right, should be shifting in ones from the left
	uint iFirstIP = (iBaseIP & mask);    //Get the first address
	int invMask = !(mask);			// make the other bits 0
	uint iLastIP = iFirstIP + invMask;
	startAddr = new IPAddress(iFirstIP);
	endAddr = new IPAddress(iLastIP);
	netmask = mask;
	addrCount = (endAddr - startAddr) + 1;

	return true;
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
			uint tmpi = atoi(quads[i].c_str());
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

bool IPAddress::isInRange(const IPAddress& toCheck)
{
		if(this->addrType == IPType::Range)
		{
			if(toCheck.addrType == IPType::Range)
			{
				//need to make sure ranges don't overlap
				return ( ( (toCheck.startAddr->intAddress <= this->endAddr->intAddress)  && (toCheck.startAddr->intAddress >= this->startAddr->intAddress) ) ||
						 ( (toCheck.endAddr->intAddress <= this->endAddr->intAddress) && (toCheck.endAddr->intAddress >= this->startAddr->intAddress) ) );
			}
			else
			{
				return (toCheck.intAddress >= this->startAddr->intAddress) && (toCheck.intAddress <= this->endAddr->intAddress);
			}
		}
		return toCheck.intAddress == this->intAddress;
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
	string cidrStr(ipStr.substr(0, ipStr.length()-1)); //We want the string minus the ending character
	
	cidrStr += "/([012]?\\d|3[012])$";

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
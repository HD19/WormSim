#include "NetMap.h"

NetworkMap::NetworkMap(string testStr)
{
	this->address = testStr;
}

NetworkMap::NetworkMap()
{
	//Construct and initialize a graph
	if(this->readConfiguration())
	{
		cout << "[+] Network graph constructed with success" << endl;
	}

	return;
}

bool NetworkMap::readConfiguration()
{
	//We're gonna practice generating a YAML file
   YAML::Emitter out;
   out << "Hello, World!";
   cout << "Here's the output YAML:\n" << out.c_str(); // prints "Hello, World!"
   return true;
}
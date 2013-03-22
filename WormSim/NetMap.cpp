#include "NetMap.h"

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
	//YAML reading magic should happen here!
	try
	{
		YAML::Node netConf = YAML::LoadFile(NET_CONFIG_PATH);
		//Get the routers
		cout << netConf["helloworld"] << endl;
		
		return true;
	}
	catch(exception& ex)
	{
		cout << "[+] Error parsing network file! " << endl << ex.what() << endl;

		return false;
	}

}
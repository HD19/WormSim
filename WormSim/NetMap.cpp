#include "NetMap.h"

NetworkMap::NetworkMap()
{
	//Construct and initialize a graph
	if(this->readConfiguration())
	{
		cout << "[+] Network graph constructed with success" << endl;
	}
	else
	{
		cout << "[+] I can't parse anything!" << endl;
	}
	return;
}

bool NetworkMap::readConfiguration()
{
	//YAML reading magic should happen here!
	try
	{
		ifstream inFile(NET_CONFIG_PATH);
		YAML::Parser ymlParser(inFile);

		YAML::Node netDoc;

		while(ymlParser.GetNextDocument(netDoc))
		{

			//If there are no maps, this won't work.
			for(YAML::Iterator it = netDoc.begin(); it != netDoc.end(); ++it)
			{
				//This will iterate throught he SEQUENCES, if there are any
				//So given the number of entries, each - starts a new one
				//Get an entry from the doc, then access keys in that one.
				string testScalar;
				const YAML::Node& tmpNode =*it;

				tmpNode["name"] >> testScalar;
				cout << "Stats for " << testScalar << endl;
				cout << "-------------------------------------" << endl;
				//This map should give another sequence
				const YAML::Node& powerNode = tmpNode["powers"];

				//Iterating through powers sequence
				for(YAML::Iterator secIt = powerNode.begin(); secIt != powerNode.end(); ++secIt)
				{
					//We should have two objects, name and damage
					const YAML::Node& thirdTempNode = (*secIt);
					string tmpName, tmpDamage;

					thirdTempNode["name"] >> tmpName;
					thirdTempNode["damage"] >> tmpDamage;

					cout << "Name: " << tmpName << " \tdamage " << tmpDamage << endl;
				}
				cout << endl;
			}
		}
		
		return true;
	}
	catch(exception& ex)
	{
		cout << "[+] Error parsing network file! " << endl << ex.what() << endl;

		return false;
	}

}
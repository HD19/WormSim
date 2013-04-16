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
		cout << "[-] Error parsing configuration file at " << NET_CONFIG_PATH << endl;
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
			//netDoc should point at the top layer, we have the following:
			//Vulnerabilities:
			//NodeTypes:
			//Gateways:
			//Routes:

			try
			{
				const YAML::Node& vulnNode = netDoc["Vulnerabilities"];

				//Vulnerabilities have  a sequence like so
				// - ID: UniqueID
				//   Desc: Some human readable description
				for( YAML::Iterator it = vulnNode.begin(); it != vulnNode.end(); it++)
				{
					//Create an object for each sequence object
					//For testing, let's just print the stuff
					Vulnerability* tmpVuln = new Vulnerability;
					//iterator should be pointing at a set entry
					(*tmpVuln) << (*it);
					vulnMap[tmpVuln->getID()] = tmpVuln;
#ifdef _DEBUG
					cout << "Added : " << "ID: " << tmpVuln->getID() << endl << "Description: " << tmpVuln->getDesc() << endl;
#endif
				}
			}
			catch(exception& ex)
			{
				cout << "[-] Error: Vulnerability section doesn't exist" << endl;
				return false;
			}
#ifdef _DEBUG
			cout << "[+] Done parsing Vulnerabilities section!" << endl;
#endif
			try
			{
				const YAML::Node& netNode = netDoc["NodeTypes"];
				for( YAML::Iterator it = netNode.begin(); it != netNode.end(); it++)
				{
					//Sequence of node types
					NodeType* tmpDesc = new NodeType;

					(*tmpDesc) << (*it);
					nodeTypeMap[tmpDesc->getID()] = tmpDesc;
				}
			
			}
			catch(exception& ex)
			{
				cout << "[-] Error: NodeType section doesn't exist" << endl;
				return false;
			}

#ifdef _DEBUG
			cout << "[+] Done parsing NodeTypes section!" << endl;
#endif
			try
			{
				const YAML::Node& gateNode = netDoc["Gateways"];
				for( YAML::Iterator it = gateNode.begin(); it != gateNode.end(); it++)
				{
					Gateway* tmpGate = new Gateway();

					(*tmpGate) << (*it);
					gatewayMap[tmpGate->gateID] = tmpGate;
				}
			}
			catch(exception& ex)
			{
				cout << "[-] Error: Gateway section doesn't exist" << endl;
				return false;
			}
#ifdef _DEBUG
			cout << "[+] Done parsing Gateways section!" << endl;
#endif
			try
			{
				//Gateways should be set. Now lets get the routes
				const YAML::Node& routeNode = netDoc["Routes"];
				for(YAML::Iterator it = routeNode.begin(); it != routeNode.end(); it++)
			{
				//Format should be GatewayID:[sequence of other gateway IDs]
				try
				{
					string gatewayKey;
					const YAML::Node& gateSequence = it.second();

					it.first() >> gatewayKey;

					if( gatewayMap.find(gatewayKey) == gatewayMap.end())
					{
						//Didn't find this gateway in the keys
						cout << "[-] Error: Gateway: " << gatewayKey << " not found in parsed gateways" << endl;
						return false;
					}

					for(unsigned int i = 0; i < gateSequence.size(); i++)
					{
						string tmpRoute;
						gateSequence[i] >> tmpRoute;
						if(gatewayMap.find(tmpRoute) == gatewayMap.end())
						{
							//Didn't find this gateway in the gateway map keys
							cout << "[-] Error: Gateway: " << tmpRoute << " not found in parsed gateways, can't create route" << endl;
							return false;
						}
						//found, push back graph connection into map
						routeMap[gatewayKey].push_back(tmpRoute); 
					}
				}
				catch(exception& ex)
				{
					cout << "[-] Error parsing routes section: " << ex.what() << endl;
					return false;
				}			
			}
			}
			catch(exception& ex)
			{
				cout << "[-] Error: Routes section doesn't exist" << endl;
				return false;
			}
		}
			/***********************************************
			 * This here's a simple example, check out example.yml to see what this parses.
			//If there are no maps, this won't work.
			//for(YAML::Iterator it = netDoc.begin(); it != netDoc.end(); ++it)
			//{
			//	//This will iterate throught he SEQUENCES, if there are any
			//	//So given the number of entries, each - starts a new one
			//	//Get an entry from the doc, then access keys in that one.
			//	string testScalar;
			//	const YAML::Node& tmpNode =*it;

			//	tmpNode["name"] >> testScalar;
			//	cout << "Stats for " << testScalar << endl;
			//	cout << "-------------------------------------" << endl;
			//	//This map should give another sequence
			//	const YAML::Node& powerNode = tmpNode["powers"];

			//	//Iterating through powers sequence
			//	for(YAML::Iterator secIt = powerNode.begin(); secIt != powerNode.end(); ++secIt)
			//	{
			//		//We should have two objects, name and damage
			//		const YAML::Node& thirdTempNode = (*secIt);
			//		string tmpName, tmpDamage;

			//		thirdTempNode["name"] >> tmpName;
			//		thirdTempNode["damage"] >> tmpDamage;

			//		cout << "Name: " << tmpName << " \tdamage " << tmpDamage << endl;
			//	}
			//	cout << endl;
			//}
		}
		***********************************************/
		return true;
	}
	catch(exception& ex)
	{
		cout << "[-] Error parsing network file! " << endl << ex.what() << endl;

		return false;
	}

}
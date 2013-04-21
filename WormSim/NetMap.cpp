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
				cout << "[-] Error: Vulnerability section doesn't exist: " << ex.what() << endl;
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
				cout << "[-] Error: NodeType section doesn't exist: " << ex.what() <<  endl;
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
				cout << "[-] Error: Gateway section doesn't exist: " << ex.what() <<  endl;
				return false;
			}
#ifdef _DEBUG
			cout << "[+] Done parsing Gateways section!" << endl;
#endif
			try
			{
				map<string, vector<string>> routeEntryMap;
				//Gateways should be set. Now lets get the routes
				const YAML::Node& routeNode = netDoc["Routes"];
				//This is a sequence of mappings
				for(YAML::Iterator it = routeNode.begin(); it != routeNode.end(); it++)
				{
					//Check example file for format
					//Looks Like:
					//Name: [OPTIONAL]
					//Address: 
					//GateType:
					//Edges:

					try
					{
						RouteEntry* tmpRoute = new RouteEntry;

						if(const YAML::Node* nameNode = (*it).FindValue("Name"))
						{
							(*nameNode) >> tmpRoute->name;
						}

						(*it)["Address"] >> tmpRoute->address;
						string tmpGWType;

						(*it)["GateType"] >> tmpGWType;

						//Find gate type in gateway map
						if(gatewayMap.find(tmpGWType) != gatewayMap.end())
						{
							tmpRoute->gateType = gatewayMap[tmpGWType];
						}

						const YAML::Node& edgeNode = (*it)["Edges"];
						string tmpKey;
		
						if( tmpRoute->name != "")
						{
							tmpKey = tmpRoute->name;
						}
						else
						{
							tmpKey = tmpRoute->address;
						
						}
						for(uint i = 0; i < edgeNode.size(); i++)
						{
							//Throw these edges into a temporary list for later resolution
							//They're a sequence of strings, dumb dumb
							string tmpStr;
							edgeNode[i] >> tmpStr;
							routeEntryMap[tmpKey].push_back( tmpStr );
						}

						this->routeList.push_back( tmpRoute );

					}
					catch(exception& ex)
					{
						cout << "[-] Error parsing routes section: " << ex.what() << endl;
						return false;
					}			
				}

				//Route entry map is filled. For each RouteEntry, resolve the edges.
				for( unsigned int i = 0; i < routeList.size(); i++)
				{
					string routeID;
					RouteEntry& tmpRoute = *(routeList[i]);

					if(tmpRoute.name != "")
					{
						routeID = tmpRoute.name;
					}
					else
					{
						routeID = tmpRoute.address;
					}

					//vector for holding the results of the RouteEntry to hold the array of pointers later
					vector<RouteEntry*> tmpVect;
					vector<string>& routeStrVect = routeEntryMap[routeID];
					//For each item in the route entry map...
					for(unsigned int k = 0; k < routeStrVect.size(); k++)
					{
						//...map the actual entry to the structure vector
						for(unsigned int j = 0; j < routeList.size(); j++)
						{
							string tmpRouteEntryStr;
							if(i == j)
							{
								continue;
							}
							
							if(routeList[j]->name != "")
							{
								tmpRouteEntryStr = routeList[j]->name;
							}
							else
							{
								tmpRouteEntryStr = routeList[j]->address;
							}
							
							if(routeStrVect[k] == tmpRouteEntryStr)
							{
								tmpVect.push_back( routeList[j] );

								break;
							}
						}
					}
					//tmpVect should now be assigned to the structure
					tmpRoute.edges = tmpVect; //Make sure this makes a deep copy
				}

			}
			catch(exception& ex)
			{
				cout << "[-] Error: Routes section doesn't exist: " << ex.what() << endl;
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
		//Now we're done reading the network configuration. Let's generate the graph and allocate addresses as necessary.
		if(generateGraph())
		{
			return true;
		}

		return false;
	}
	catch(exception& ex)
	{
		cout << "[-] Error parsing network file! " << endl << ex.what() << endl;

		return false;
	}
}

bool NetworkMap::generateGraph()
{
	//For each route entry...
	for(RouteVectorIter it = routeList.begin(); it != routeList.end(); it++)
	{
		//... Check the route-entry's gateway type
		RouteEntry* curRouteEntry = (*it);
		
		if(gatewayMap.find(curRouteEntry->gateType->gateID) == gatewayMap.end())
		{
			cout << "[-] Error genertating route graph: couldn't find route gate type: " << curRouteEntry->gateType << " in gateway map!" << endl;
			return false;
		}

		Gateway* curGateway = gatewayMap[curRouteEntry->gateType];

		//For this gateway, we have to generate a subnet of nodes

	}
	return false;
}
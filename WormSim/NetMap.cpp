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

NetworkMap::NetworkMap(MyRNG* randomGen)
{
	theRNG = randomGen;
	
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

void NetworkMap::setRNG(MyRNG* randomGen)
{
	theRNG = randomGen;
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
					tmpGate->setRNG(theRNG);
					(*tmpGate) << (*it);
					gatewayMap[tmpGate->gateID] = tmpGate;

					//need to resolve node types
					for(uint i = 0; i < tmpGate->nodeTypesToAdd.size(); i++)
					{
						const vector<string>& toRes = tmpGate->nodeTypesToAdd;

						if(nodeTypeMap.find(toRes[i]) == nodeTypeMap.end())
						{
							string exceptStr = "NodeType " + toRes[i] + " not recognized!";
							throw new exception(exceptStr.c_str());
						}

						tmpGate->nodeTypes.push_back(nodeTypeMap[toRes[i]]);
					}
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

//Allocate a free IP block based on the requested start address and the number of mask bits
//If this fails, it should return a null pointer.
//If a null pointer comes back, it's the users fault for specifying an already allocated IP block
IPAddress* NetworkMap::getIPBlock(string& inAddr, unsigned int maskBits)
{
	//string input is an address.
	//If the block won't fit anywhere, return a null pointer
	IPAddress* toRet = NULL;
	IPAddress  tmp(inAddr);

	for(unsigned int i = 0; i < allocatedIPs.size(); i++)
	{
		IPAddress& curIP = (*allocatedIPs[i]);
		if(tmp.isInRange(curIP))
		{
			//ToRet should be NULL
			return toRet;
		}
	}

	toRet = new IPAddress(inAddr);
	return toRet;
}

//Allocate a free IP block based on the requested address size
IPAddress* NetworkMap::getIPBlock(unsigned int maskbits)
{
	IPAddress* toRet = NULL;
	//Use IPAddress to check address.
	IPAddress tmpIP = IPAddress::generateRandomBlock(theRNG, maskbits);


	//Get an IP that isn't in the way of anyone
	for(unsigned int i = 0; i < allocatedIPs.size(); i++)
	{
		IPAddress& curIP = (*allocatedIPs[i]);
		while(tmpIP.isInRange(curIP))
		{
			//WARNING: might eat up memory if this is implemented incorrectly
			tmpIP = IPAddress::generateRandomBlock(theRNG, maskbits);
		}
	}

	toRet = new IPAddress(tmpIP);
	//this gives a free IP block, make a copy then return it.
	return toRet;
}

GateInstance* NetworkMap::buildGateInstance(RouteEntry* routeEntry)
{

	//Do all the stuff to build a GateInstance here.
	Gateway* curGateway = gatewayMap[routeEntry->gateType->gateID];

	//For this gateway, we have to generate a subnet of nodes
	//Allocate address
	IPAddress* freeAddrBlock = NULL;
	
	//If this is AUTO then there's no way we've evaluated this yet.
	if(routeEntry->address == "AUTO")
	{
		freeAddrBlock = getIPBlock(curGateway->maskBits);
		routeEntry->address = freeAddrBlock->getStrRep();
	}
	else
	{
		freeAddrBlock = getIPBlock(routeEntry->address, curGateway->maskBits);
	}
	//This block is illegal, no space, or something went wrong.
	if(!freeAddrBlock)
	{
		return NULL;
	}
	//store the allocated block for later checking
	allocatedIPs.push_back(freeAddrBlock);

	//Generate gatewayInstance
	//This is done by adding a vertex to the graph
	vertexMap[routeEntry->address] = boost::add_vertex(this->netGraph); //add the new vertex, add the vertex to the vertex map.

	Graph::vertex_descriptor& curVD = vertexMap[routeEntry->address];

	GateInstance& curGateNode = netGraph[curVD];

	//Set gateway information
	curGateNode.gateway = curGateway;

	//Set the node property address block
	curGateNode.addressBlock = freeAddrBlock;
		 
	//build the list of nodes
	curGateway->generateSubGraph( &(curGateNode.nodes) );

	return &curGateNode;
}

bool NetworkMap::generateGraph()
{

	//Use fancy new C++11 random module
	//Lets assume it was seeded already.
	//Have to create a distribution
	std::uniform_int_distribution<uint32_t> nodeDist(0, nodeTypeMap.size());


	//For each route entry...
	for(RouteVectorIter it = routeList.begin(); it != routeList.end(); it++)
	{
		//... Check the route-entry's gateway type
		RouteEntry* curRouteEntry = (*it);
		
		if(gatewayMap.find(curRouteEntry->gateType->gateID) == gatewayMap.end())
		{
			cout << "[-] Error generating route graph: couldn't find route gate type: " << curRouteEntry->gateType << " in gateway map!" << endl;
			return false;
		}
		GateInstance* curGateInstance = NULL;
		//Need to make sure we didn't already create a route for this.
		if(vertexMap.find(curRouteEntry->address) != vertexMap.end())
		{
			//we already created this node!
#if _DEBUG
			cout << "[!] Already have an entry for : " << curRouteEntry->address << endl;
#endif
			//Continue processing it's route list!
			Graph::vertex_descriptor& sVD = vertexMap[curRouteEntry->address];
			curGateInstance = &netGraph[sVD];

		}
		else
		{
			curGateInstance = buildGateInstance(curRouteEntry);
		}
		if(!curGateInstance)
		{
			cout << "[-] Error generating new gateway instances for route entry: " << curRouteEntry->address << endl;
			return false;
		}

		//This node should be set. Create and resolve edges now.
		vector<RouteEntry*>& curEdges = curRouteEntry->edges;

		for(uint i = 0; i < curEdges.size(); i++)
		{
			GateInstance* tmpGateInstance = NULL;
			//We should create the GateInstance object for each route entry, then add an edge
			if(vertexMap.find(curEdges[i]->address) == vertexMap.end())
			{
				tmpGateInstance = buildGateInstance(curEdges[i]);
				if(!tmpGateInstance)
				{
					cout << "[-] Error generating new gateway instance for route entry: " << curRouteEntry->address << endl;
					return false;
				}
			}
			//If we're here, the two vertexes should exist.
			try
			{
				Graph::vertex_descriptor& curVD = vertexMap[curEdges[i]->address]; //Vertex descriptor of the current gate instance
				Graph::vertex_descriptor& tmpVD = vertexMap[curRouteEntry->address]; //Vertex descriptor that needs an edge added to the current gate instance
				boost::add_edge(curVD, tmpVD, netGraph);
			}
			catch(exception& ex)
			{
				cout << "[-] Error adding edge between routes: " << curEdges[i]->address << " and " << curRouteEntry->address << " " << ex.what() << endl;
				return false;
			}
		}
	}

	return true;
}
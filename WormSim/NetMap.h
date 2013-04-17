#ifndef _NETMAP_H
#define _NETMAP_H

#include <iostream>
#include <string>
#include <fstream>
#include "NetNode.h"


#define NET_CONFIG_PATH "network.yml"


using namespace std;

class NetworkMap
{
public:
	NetworkMap();
private:
	bool readConfiguration();
	uint numNodes;
	string description;
	string address;
	Graph netGraph;
	map<string, Vulnerability*> vulnMap;
	map<string, NodeType*> nodeTypeMap;
	map<string, Gateway*> gatewayMap;
	vector<RouteEntry*> routeList;

};

#endif

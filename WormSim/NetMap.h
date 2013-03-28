#ifndef _NETMAP_H
#define _NETMAP_H

#include <iostream>
#include <string>
#include <fstream>
#include <boost\graph\undirected_graph.hpp>
#include "NetNode.h"


#define NET_CONFIG_PATH "network.yml"

typedef boost::undirected_graph<> Graph;

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
	map<string, NodeDescriptor*> nodeTypeMap;

};

#endif

#ifndef _NETMAP_H
#define _NETMAP_H

#include <iostream>
#include <string>
#include <boost\graph\undirected_graph.hpp>
#include "NetNode.h"


typedef boost::undirected_graph<> Graph;

using namespace std;

class NetworkMap
{
public:
	NetworkMap();
	NetworkMap(string testStr);
private:
	bool readConfiguration();
	uint numNodes;
	string description;
	string address;
	Graph netGraph;
	vector<NodeDescriptor*> nodeTypes; //Defines all the different node types.

};

#endif
